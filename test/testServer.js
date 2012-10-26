var express 		= require('express'),
	app 			= express(),
	nodeFbAuth 		= new require('../lib/nodeFbAuth')(),
	redis_store     = require('connect-redis')(express);

var fb_data = {
	app_id: 		'facebook-app-id',
	app_secret: 	'facebook-app-secret',
	base_url: 		'http://your-callback-url',
	permissions: 	'list,of,permissions'
};

app.configure(function(){
	app.use(express.cookieParser('somesecretkey'));
	app.use(express.session({
			secret: 'secretsessionkey',
			store: new redis_store({
				host: '127.0.0.1',
				port: '6379',
				db: 1,
				prefix: 'fb_auth'
			})
		}
	));
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

app.listen(4000);