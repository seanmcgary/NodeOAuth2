var express 		= require('express'),
	app 			= express(),
	nodeOAuth2 		= require('../lib/NodeOAuth2'),
	redis_store     = require('connect-redis')(express);

var fb_data = {
	app_id: 		'158731967622039',
	app_secret: 	'32ff23cbdf3691b8f2c336e511105b6f',
	base_url: 		'http://localhost:9000',
	permissions: 	'publish_stream,email,status_update,publish_actions'
};

var googleData = {
	app_id: 		'',
	app_secret: 	'',
	base_url: 		'http://localhost:9000',
	permissions: 	'https://www.googleapis.com/auth/plus.login+https://www.googleapis.com/auth/userinfo.email'
};

var nodeFbAuth = nodeOAuth2.createHandler('facebook');
var nodeGoogleAuth = nodeOAuth2.createHandler('google');

app.configure(function(){
	app.use(express.cookieParser());
	app.use(express.session({
			secret: 'a4e485c37bf85f182de00c6ef2fbb4adc5490ad3',
			store: new redis_store({
				host: '127.0.0.1',
				pass: 'rids899*baby',
				port: '6379',
				db: 2,
				prefix: '_auth'
			})
		}
	));
});

nodeGoogleAuth.initialize({
	app_id: 		googleData.app_id, 
	app_secret: 	googleData.app_secret, 
	base_url: 		googleData.base_url,
	permissions: 	googleData.permissions,
	app: 			app
});

// this will initialize the proper facebook routes
// for express
nodeFbAuth.initialize({
	app_id: 		fb_data.app_id, 
	app_secret: 	fb_data.app_secret, 
	base_url: 		fb_data.base_url,
	permissions: 	fb_data.permissions,
	app: 			app
});

app.get('/', function(req, res){
	res.json(req.session);
});

app.listen(9000);