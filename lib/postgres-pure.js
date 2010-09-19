/*
Copyright (c) 2010 Tim Caswell <tim@creationix.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

var crypto = require('crypto'),
    net = require("net"),
    sys = require("sys"),
    sqllib = require('./sql'),
    url = require('url'),
	PostgresReader=require("./PostgresReader").PostgresReader,
	PostgresEncoder=require("./PostgresEncoder").PostgresEncoder,
	BufferQueueReader=require("bufferlib/BufferQueueReader").BufferQueueReader;

exports.DEBUG = 0;

function encoder(header) {
	return new PostgresEncoder(header);
  /*header = header || "";
  var w = Buffer.makeWriter();
  w.frame = function frame() {
    var message = w.toBuffer();
    var buffer = new Buffer(message.length + 4 + header.length);
    var offset = 0;
    if (header.length > 0) {
      buffer.write(header, 'ascii', offset);
      offset += header.length;
    }
    buffer.int32Write(message.length + 4, offset);
    offset += 4;
    message.copy(buffer, offset);
    return buffer;
  }
  return w;*/
}

// http://www.postgresql.org/docs/8.3/static/protocol-message-formats.html
var formatter = {
  CopyData: function () {
    // TODO: implement
  },
  CopyDone: function () {
    // TODO: implement
  },
  Describe: function (name, type) {
    return (encoder('D'))
      .pushString(type)
      .pushStringZero(name);
  },
  Execute: function (name, max_rows) {
    return (encoder('E'))
      .pushStringZero(name)
      .pushIntBE(max_rows,4);
  },
  Flush: function () {
    return encoder('H');
  },
  FunctionCall: function () {
    // TODO: implement
  },
  Parse: function (name, query, var_types) {
    var builder = (encoder('P'))
      .pushStringZero(name)
      .pushStringZero(query)
      .pushIntBE(var_types.length,2);
    var_types.each(function (var_type) {
      builder.pushIntBE(var_type,4);
    });
    return builder;
  },
  PasswordMessage: function (password) {
    return (encoder('p'))
      .pushStringZero(password);
  },
  Query: function (query) {
    return (encoder('Q'))
      .pushStringZero(query);
  },
  SSLRequest: function () {
    return (encoder())
      .pushIntBE(0x4D2162F,4);
  },
  StartupMessage: function (options) {
    // Protocol version number 3
    return encoder()
      .pushIntBE(0x30000,4)
      .pushHash(options);
  },
  Sync: function () {
    return encoder('S');
  },
  Terminate: function () {
    return encoder('X');
  }
};

// Parse response streams from the server
function parse_response(code, buffer) {
  var input, type, args, num_fields, data, size, i;
  reader = new PostgresReader(buffer);
  args = [];
  switch (code) {
  case 'R':
    switch (reader.popIntBE(4)) {
    case 0:
      type = "AuthenticationOk";
      break;
    case 2:
      type = "AuthenticationKerberosV5";
      break;
    case 3:
      type = "AuthenticationCleartextPassword";
      break;
    case 4:
      type = "AuthenticationCryptPassword";
      args = [reader.popString(2)];
      break;
    case 5:
      type = "AuthenticationMD5Password";
      args = [reader.popBuffer(4)];
      break;
    case 6:
      type = "AuthenticationSCMCredential";
      break;
    case 7:
      type = "AuthenticationGSS";
      break;
    case 8:
      // TODO: add in AuthenticationGSSContinue
      type = "AuthenticationSSPI";
      break;
    default:
    
      break;
    }
    break;
  case 'E':
    type = "ErrorResponse";
    args = [{}];
    reader.popMultiStringZero().forEach(function (field) {
      args[0][field[0]] = field.substr(1);
    });
    break;
  case 'S':
    type = "ParameterStatus";
    args = [reader.popStringZero(), reader.popStringZero()];
    break;
  case 'K':
    type = "BackendKeyData";
    args = [reader.popIntBE(4), reader.popIntBE(4)];
    break;
  case 'Z':
    type = "ReadyForQuery";
    args = [reader.popString(1)];
    break;
  case 'T':
    type = "RowDescription";
    num_fields = reader.popIntBE(2);
    data = [];
    for (i = 0; i < num_fields; i += 1) {
      data.push({
        field: reader.popStringZero(),
        table_id: reader.popIntBE(4),
        column_id: reader.popIntBE(2),
        type_id: reader.popIntBE(4),
        type_size: reader.popIntBE(2),
        type_modifier: reader.popIntBE(4),
        format_code: reader.popIntBE(2)
      });
    }
    args = [data];
    break;
  case 'D':
    type = "DataRow";
    data = [];
    num_fields = reader.popIntBE(2);
    for (i = 0; i < num_fields; i += 1) {
      size = reader.popIntBE(4);
      if (size>>0 === -1) {
        data.push(null);
      } else {
        data.push(reader.popString(size));
      }
    }
    args = [data];
    break;
  case 'C':
    type = "CommandComplete";
    args = [reader.popStringZero()];
    break;
  case 'N':
    type = "NoticeResponse";
    args = [{}];
    reader.popMultiStringZero().forEach(function (field) {
      args[0][field[0]] = field.substr(1);
    });
    break;
  }
  if (!type) {
    sys.debug("Unknown response " + code);  
  }
  return {type: type, args: args};
}


function Connection(args) {
  if (typeof args === 'string') {
    args = url.parse(args);
    args.database = args.pathname.substr(1);
    args.auth = args.auth.split(":");
    args.username = args.auth[0];
    args.password = args.auth[1];
  }
  var started, conn, connection, events, query_queue, row_description, query_callback, results, readyState, closeState;
  
  // Default to port 5432
  args.port = args.port || 5432;

  // Default to host 127.0.0.1
  args.hostname = args.hostname || "127.0.0.1";


  connection = net.createConnection(args.port, args.hostname);
  events = new process.EventEmitter();
  query_queue = [];
  readyState = false;
  closeState = false;
  started = false;
  conn = this;
  
  // Disable the idle timeout on the connection
  connection.setTimeout(0);

  // Sends a message to the postgres server
  function sendMessage(type, args) {
    var buffer = (formatter[type].apply(this, args)).frame();
    if (exports.DEBUG > 0) {
      sys.debug("Sending " + type + ": " + JSON.stringify(args));
      if (exports.DEBUG > 2) {
        sys.debug("->" + buffer.inspect().replace('<', '['));
      }
    }
    connection.write(buffer);
  }
  
  var queue = new BufferQueueReader();
  function checkInput() {
    while (queue.length>=5) {
		var code = queue.readChar(0);
		var length = queue.readIntBE(1,4) - 4;
		
		// Make sure we have a whole message, TCP comes in chunks
		if (queue.length < length + 5) {
			return;
		}
		queue.skip(5);
		var message = queue.popBuffer(length);

		if (exports.DEBUG > 1) {
		  sys.debug("stream: " + code + " " + message.inspect());
		}
		command = parse_response(code, message);
		if (command.type) {
		  if (exports.DEBUG > 0) {
			sys.debug("Received " + command.type + ": " + JSON.stringify(command.args));
		  }
		  command.args.unshift(command.type);
		  events.emit.apply(events, command.args);
		}
	}
  }
    
  // Set up tcp client
  connection.addListener("connect", function () {
    sendMessage('StartupMessage', [{user: args.username, database: args.database}]);
  });
  connection.addListener("data", function (data) {
    if (exports.DEBUG > 2) {
      sys.debug("<-" + data.inspect());
    }
    queue.push(data);
    checkInput();
  });
  connection.addListener("end", function (data) {
    connection.end();
  });
  connection.addListener("disconnect", function (had_error) {
    if (had_error) {
      sys.debug("CONNECTION DIED WITH ERROR");
    }
  });

  // Set up callbacks to automatically do the login and other logic
  events.addListener('AuthenticationMD5Password', function (salt) {
    var result = "md5" + md5(md5(args.password + args.username) + salt.toString("binary"));
    sendMessage('PasswordMessage', [result]);
  });
  events.addListener('AuthenticationCleartextPassword', function () {
    sendMessage('PasswordMessage', [args.password]);
  });
  events.addListener('ErrorResponse', function (e) {
    conn.emit('error', e.S + ": " + e.M);
    if (e.S === 'FATAL') {
      connection.end();
    }
  });
  events.addListener('ReadyForQuery', function () {
    if (!started) {
      started = true;
      conn.emit('connection');
    }
    if (query_queue.length > 0) {
      var query = query_queue.shift();
      query_callback = query.callback;
      row_callback = query.row_callback;
	  results = [];
      sendMessage('Query', [query.sql]);
      readyState = false;
    } else {
      if (closeState) {
        connection.end();
      } else {
        readyState = true;      
      }
    }
  });
  events.addListener("RowDescription", function (data) {
    row_description = data;
    results = [];
  });
  events.addListener("DataRow", function (data) {
    var row, i, l, description, value;
    row = {};
    l = data.length;
    for (i = 0; i < l; i += 1) {
      description = row_description[i];
      value = data[i];
      if (value !== null) {
        // TODO: investigate to see if these numbers are stable across databases or
        // if we need to dynamically pull them from the pg_types table
        switch (description.type_id) {
        case 16: // bool
          value = value === 't';
          break;
        case 20: // int8
        case 21: // int2
        case 23: // int4
          value = parseInt(value, 10);
          break;
        }
      }
      row[description.field] = value;
    }
    if (row_callback) {
      row_callback(row);
    } else {
      results.push(row);
    }
  });
  events.addListener('CommandComplete', function (data) {
    var tag = data.split (" ");
    query_callback.call(this, null, results, tag.slice (1, tag.length));
  });
  
  conn.execute = function (sql/*, *parameters*/) {
    var parameters = Array.prototype.slice.call(arguments, 1);
    var callback = parameters.pop();

    // Merge the parameters in with the sql if needed.
    sql = sqllib.merge(sql, parameters);
    
    // TODO: somehow give the query_queue a hint that this isn't query and it
    // can optimize.
    query_queue.push({sql: sql, callback: function () {
      callback();
    }});
    
    if (readyState) {
      events.emit('ReadyForQuery');
    }
    
  };

  conn.query = function query(sql/*, *parameters, row_callback*/) {
    var row_callback, parameters, callback;

    // Grab the variable length parameters and the row_callback is there is one.
    parameters = Array.prototype.slice.call(arguments, 1);
    callback = parameters.pop();
    if (typeof parameters[parameters.length - 1] === 'function') {
      row_callback = parameters.pop();
    }

    // Merge the parameters in with the sql if needed.
    if (parameters.length > 0) {
      sql = sqllib.merge(sql, parameters);
    }

    if (row_callback) {
      query_queue.push({sql: sql, row_callback: row_callback, callback: function () {
        callback();
      }});
    } else {
      query_queue.push({sql: sql, callback: function (err, data, tag) {
		if (tag !== undefined) {
			callback (err, data, tag);
		} else {
			callback (err, data);
		}
      }});
    }
    
    if (readyState) {
      events.emit('ReadyForQuery');
    }
    
  };
  
  this.end = function () {
    closeState = true;

    // Close the connection right away if there are no pending queries
    if (readyState) {
      connection.end();
    }
  };
}
Connection.prototype = new process.EventEmitter();
Connection.prototype.get_store = function (name, columns) {
  return new sqllib.Store(this, name, columns, {
    do_insert: function (data, keys, values, callback) {
      this.conn.query("INSERT INTO " +
        this.name + "(" + keys.join(", ") + ")" +
        " VALUES (" + values.join(", ") + ")" +
        " RETURNING _id",
        function (result) {
          data._id = parseInt(result[0]._id, 10);
          callback(null, data._id);
        }
      );
    },
    index_col: '_id',
    types: ["_id SERIAL"]
  });
};

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

exports.Connection = Connection;
