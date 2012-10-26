var express 		= require('express'),
	app 			= express(),
	nodeFbAuth 		= new require('../lib/nodeFbAuth')(),
	redis_store     = require('connect-redis')(express);

var fb_data = {
	app_id: '434094643315729',
	app_secret: 'cd787c75f7c5b731479db8c96f9cca14',
	base_url: 'http://oauth.dev.klout.com:4000'
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

nodeFbAuth.initialize({
	app_id: fb_data.app_id, 
	app_secret: fb_data.app_secret, 
	base_url: fb_data.base_url,
	permissions: 'email,read_stream,offline_access',
	app: app

});


app.get('/', function(req, res){
	res.json(req.session);
});

app.listen(4000);