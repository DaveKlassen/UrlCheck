// Use these constants
const {CONSTANTS} = require('./lib/CONSTANTS');
const {CONFIG} = require('./lib/CONSTANTS');

var application_root = __dirname,
  fs = require('fs'),
  path = require('path'),
  assert = require('assert'),
  lutils = require('./lib/local_utils'),
  fileStreamRotator = require('file-stream-rotator'),
  express = require('express'),
  app = express(),
  bodyParser = require('body-parser'),

  https = require('https'),
  http = require('http'),
  morgan = require('morgan'),
  MongoClient = require('mongodb').MongoClient,
  events = require('events'),

  // If you would like to modify these settings create a json_data/server.json file.
  // For an example see the file json_data/envsave.json
  WWW_REDIRECT = true,
  SSL_DIR = "./",
  EXTERNAL_PORT = 80,
  EXTERNAL_HOST = "www.urlcheck.org",
  EXTERNAL_PROTOCOL = "http://",
  EXTERNAL_HOST_PORT = EXTERNAL_PROTOCOL + EXTERNAL_HOST,

  DB_HOST = "",
  DB_USER = "",
  DB_PASS = "",

  DB_IMPL = "mongo",
  MONGO_HOST_PORT = "mongodb://localhost:27017/",
  WEB_APP = "urlcheck",
  WEB_APP_DB = MONGO_HOST_PORT + WEB_APP,
  OWNER_EMAIL_ADDR = '"Admin" <dbavedb@shaw.ca>';


// Initialize the event emissions
var eventEmitter = new events.EventEmitter();

// Initialize the log directory
fs.existsSync(CONFIG.LOG_DIRECTORY) || fs.mkdirSync(CONFIG.LOG_DIRECTORY);

// create a rotating write stream
var accessLogStream = fileStreamRotator.getStream({
  date_format: 'YYYYMMDD',
  filename: path.join(CONFIG.LOG_DIRECTORY, 'access-%DATE%.log'),
  frequency: 'weekly',
  verbose: false
});

// setup the logger
app.use(morgan('combined', {stream: accessLogStream}));

// If required override the above settings from a local file.
getCurrentEnvironment();

// Setup the webserver
app.set('port', EXTERNAL_PORT);
//app.use('/', express.static(CONFIG.WEB_SERVER_ROOT));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

// Start the HTTPS server
if (443 === EXTERNAL_PORT) {
  lutils.multiLog('SSL Directory : ' + SSL_DIR);

  var httpsOptions = {
    ca: fs.readFileSync(SSL_DIR + 'urlcheck-ca.crt'),
    cert: fs.readFileSync(SSL_DIR + 'urlcheck.crt'),
    key: fs.readFileSync(SSL_DIR + 'urlcheck.key')
  };
  https.createServer(httpsOptions, app).listen(443);
} else {

  // If we are not running https on 443 there is no need to a redirect server.
  if (false !== WWW_REDIRECT) {
    WWW_REDIRECT = "Not Required";
  }
  app.listen(app.get('port') );
}
lutils.multiLog("PostConfig Site: " + EXTERNAL_HOST_PORT);
lutils.multiLog("Server started on Port: " + app.get('port') );
lutils.multiLog('Backend Storage Driver: ' + DB_IMPL);
lutils.multiLog('Using Admin e-mail address of: ' + OWNER_EMAIL_ADDR);
lutils.multiLog('Using DB_HOST of: ' + DB_HOST);

if (true === WWW_REDIRECT) {
  // Redirect port 80 to 443
  var redirectApp = express () ,
  redirectServer = http.createServer(redirectApp);
  redirectApp.use(function requireHTTPS(req, res, next) {
    if (!req.secure) {
      var redirectLocation = 'https://' + EXTERNAL_HOST;  //req.headers.host
      if (undefined !== EXTERNAL_PORT) {

        // If there is a special port supplied use it.
        if ( (null !== EXTERNAL_PORT) && ("" !== EXTERNAL_PORT) && (443 !== EXTERNAL_PORT) && ("443" !== EXTERNAL_PORT) ) {
          redirectLocation = redirectLocation + ":" + EXTERNAL_PORT
        }
      }
    redirectLocation = redirectLocation + req.url;
      lutils.multiLog("Redirecting client to secure service: " + redirectLocation);
      return res.redirect(redirectLocation);
    }
    next();
  })
  redirectServer.listen(80);
  lutils.multiLog("Redirect Server on Port 80: Started");
} else {
  if (false === WWW_REDIRECT) {
    lutils.multiLog("Redirect Server on Port 80: Not Configured");
  } else {
    lutils.multiLog("Redirect Server on Port 80: " + WWW_REDIRECT);
  }
}

function vetUrlAgainstDb(response, callback) {

  // Check if this host port combination is in the db
  MongoClient.connect(WEB_APP_DB, function(err, db) {
    if (err) {
      lutils.multiLog("Connect Error - on call to vet URL : " + err);
    } else {
      let collection = db.collection(CONSTANTS.DENY_URL_COLLECTION);
      let query = { url: response.url }
      collection.findOne(query, function(err2, result) {
        if (err2) {
          lutils.multiLog("Error - in Mongo Host Find Call");
          console.log(err2);
        } else {
          lutils.multiLog("Find returned: " + result);
          console.log(result);
        }

        // Allow the caller to process the results.
        callback(err2, result);
      });
      db.close();
    }
  });

  return response;
}

function vetHostAgainstDb(response, callback) {

  // Check if this host port combination is in the db
  MongoClient.connect(WEB_APP_DB, function(err, db) {
    if (err) {
      lutils.multiLog("Connect Error - on call to vet Host : " + err);
    } else {
      let collection = db.collection(CONSTANTS.DENY_HOST_COLLECTION);
      let query = { host: response.host, port: response.port }
      collection.findOne(query, function(err2, result) {
        if (err2) {
          lutils.multiLog("Error - in Mongo Host Find Call");
          console.log(err2);
        } else {
          lutils.multiLog("Find returned: " + result);
          console.log(result);
        }

        // Allow the caller to process the results.
        callback(err2, result);
      });
      db.close();
    }
  });

  return response;
}

function getHostToVet(response) {
  let slashedArray = response.query.split('/');

  //console.log(slashedArray);
  if ( (slashedArray.length < 2) || (slashedArray[0] === '') ) {
    response.host = CONSTANTS.NO_HOST;
    response.reason = CONSTANTS.DENY_NO_HOST;
    response.status = CONSTANTS.DENIED;
  } else {

    // Set the url requested
    let urlData = response.query.split(slashedArray[0]);
    response.url = urlData[1];

    // Check if a port has been given
    let hostData = slashedArray[0].split(/[_:]+/);
    //console.log(hostData);
    response.host = hostData[0];

    // If no port is given assume port 80
    if (hostData.length < 2) {
      response.port = 80;
    } else if (hostData.length === 2) {

      // Parse the port given (Must be an integer)
      let portInteger = parseInt(hostData[1]);
      //console.log(portInteger);
      if ( (portInteger < 0) || (isNaN(portInteger)) ) {
        response.port = portInteger;
        response.reason = CONSTANTS.PORT_FORMAT + " given = " + hostData[1];
        response.status = CONSTANTS.DENIED;
      } else {
        response.port = portInteger;
      }
    } else {
      // If more than one port is given deny
      response.reason = CONSTANTS.HOST_FORMAT + " given = " + slashedArray[0];
      response.status = CONSTANTS.DENIED;
    }
  }

  return(response);
}

function getQueryToVet(receivedUrl) {
  let response = { status : CONSTANTS.WARNING,
                   reason : CONSTANTS.DEFAULT_WARNING,
                   query : receivedUrl
                  };

  // Capture our queryInfo
  let splitUrl = receivedUrl.split(CONSTANTS.BASE_URI);
  if (splitUrl.length === 2) {
    let checkData = splitUrl[1];

    response.status = CONSTANTS.PROCESSING;
    response.reason = CONSTANTS.STILL_PROCESSING;
    response.query = checkData;
    response = getHostToVet(response);
  } else {
    response.reason = CONSTANTS.UNEXPECTED_WARNING;
  }

  return(response);
}

/* Entry REST handler to verify the URL is  */
app.get(CONSTANTS.BASE_URI + '*', function(req, res) {

  // Fetch the requested data to vet
  let resData = getQueryToVet(req.url)
  if (resData.status === CONSTANTS.PROCESSING) {

    // Check if the provided host is black listed.
    vetHostAgainstDb(resData, function(error, result) {
      if (error) {
        // If we are no longer processing return the response.
        resData.status = CONSTANTS.WARNING;
        resData.reason = CONSTANTS.HOST_DB_ERROR;
        lutils.multiLog(resData.status + " " + resData.reason + " " + resData.query);
        res.end(JSON.stringify(resData));
      } else if (result === null) {
        resData.status = CONSTANTS.APPROVED;
        resData.reason = CONSTANTS.HOST_NOT_FOUND;

        // Check if the provided URL is black listed.
        vetUrlAgainstDb(resData, function(error, result) {
          if (error) {
            resData.status = CONSTANTS.WARNING;
            resData.reason = CONSTANTS.URL_DB_ERROR;
          } else if (result === null) {
            resData.status = CONSTANTS.APPROVED;
            resData.reason = CONSTANTS.URL_NOT_FOUND;

          } else {
            resData.status = CONSTANTS.DENIED;
            resData.reason = CONSTANTS.BAD_URL_FOUND;
          }

          /*
           * Note we could use EventEmitter with a timeout to ensure the
           * check completes in a certain amount of time, however given
           * the importance of this service db search speed should meet
           * an expect QoS requirement.
           */
          lutils.multiLog(resData.status + " " + resData.reason + " " + resData.query);
          res.end(JSON.stringify(resData));
        });
      } else {

        // If we are no longer processing return the response.
        resData.status = CONSTANTS.DENIED;
        resData.reason = CONSTANTS.BAD_HOST_FOUND;
        lutils.multiLog(resData.status + " " + resData.reason + " " + resData.query);
        res.end(JSON.stringify(resData));
      }
    });
  } else {
    lutils.multiLog(resData.status + " " + resData.reason);
    res.end(JSON.stringify(resData));
  }
});

/**
 **  Utility functions
 **/
function getCurrentEnvironment() {
  lutils.multiLog("Using Build Number: " + CONSTANTS.BUILD_NUMBER);

  var jsonData = getFsFile(CONSTANTS.SERVER_CONF_FILE);
  lutils.multiLog("PreConfig Site: " + EXTERNAL_HOST_PORT);
  if (jsonData.length <= 0) {
    lutils.multiLog("No configruation data in '" + CONSTANTS.SERVER_CONF_FILE + "'.");
  } else {
    try {
      var env = JSON.parse(jsonData);

      // Override the local variables only if they are actually present/defined the config file.
      if ( (undefined !== env.DB_HOST) && (null !== env.DB_HOST) && ("" !== env.DB_HOST) ) {
        DB_HOST = env.DB_HOST;
      }
      if ( (undefined !== env.DB_USER) && (null !== env.DB_USER) && ("" !== env.DB_USER) ) {
        DB_USER = env.DB_USER;
      }
      if ( (undefined !== env.DB_PASS) && (null !== env.DB_PASS) && ("" !== env.DB_PASS) ) {
        DB_PASS = env.DB_PASS;
      }
      if ( (undefined !== env.OWNER_EMAIL_ADDR) && (null !== env.OWNER_EMAIL_ADDR) && ("" !== env.OWNER_EMAIL_ADDR) ) {
        OWNER_EMAIL_ADDR = env.OWNER_EMAIL_ADDR;
      }
      if ( (undefined !== env.EXTERNAL_PORT) && (null !== env.EXTERNAL_PORT) && ("" !== env.EXTERNAL_PORT) ) {
        EXTERNAL_PORT = env.EXTERNAL_PORT;
      }
      if ( (undefined !== env.EXTERNAL_HOST) && (null !== env.EXTERNAL_HOST) && ("" !== env.EXTERNAL_HOST) ) {
        EXTERNAL_HOST = env.EXTERNAL_HOST;
      }
      if ( (undefined !== env.EXTERNAL_PROTOCOL) && (null !== env.EXTERNAL_PROTOCOL) && ("" !== env.EXTERNAL_PROTOCOL) ) {
        EXTERNAL_PROTOCOL = env.EXTERNAL_PROTOCOL;
      }
      if ( (undefined !== env.SSL_DIR) && (null !== env.SSL_DIR) && ("" !== env.SSL_DIR) ) {
        SSL_DIR = env.SSL_DIR;
      }
      if ( (undefined !== env.DB_IMPL) && (null !== env.DB_IMPL) && ("" !== env.DB_IMPL) ) {
        DB_IMPL = env.DB_IMPL;
      }
      if ( (undefined !== env.WWW_REDIRECT) && (null !== env.WWW_REDIRECT) && ("" !== env.WWW_REDIRECT) ) {
        WWW_REDIRECT = env.WWW_REDIRECT;
      }

      // Recreate the dynamic variables.
      EXTERNAL_HOST_PORT = EXTERNAL_PROTOCOL + EXTERNAL_HOST + ':' + EXTERNAL_PORT;
    } catch (e) {

      // It isn't accessible
      lutils.multiLog("Error reading '" + CONSTANTS.SERVER_CONF_FILE + "'' json data.");
    }
  }
}

function multiLog(stuff) {
  stuff = Date() + " : " + stuff;
  console.log(stuff);
  fs.appendFile(
    CONFIG.SERVER_LOG_FILE,
    stuff + '\r\n',
    {flags: 'a+', encoding: 'utf8'},
    function(err) {
      if (!err) {return;}
      setTimeout(function() {console.log(err);});
    }
  );
}

/*
 *  Methods to retrieve/store file based information.
 */
function getFsFile(dataFile) {
  //var sessionFile = "json_data/session";
  var data = '';

  try {
    fs.accessSync(dataFile, fs.F_OK);
    data = fs.readFileSync(dataFile, 'utf8');
    lutils.multiLog("We have a read config file: " + dataFile ); //+ " Cookie?: " + data);
  } catch (e) {

    // It isn't accessible
    lutils.multiLog("No pre-existing '" + dataFile + "'' file is available.");
  }

  return(data);
}

/*
app.get('*', (req, res) => {
  switch (req.url) {

    default:
      // If the route is not in our list... redirect to 404
      res.redirect("/error404");
  }
})*/
