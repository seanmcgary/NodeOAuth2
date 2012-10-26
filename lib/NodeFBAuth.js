var hash 	= require('hashlib2'),
	https 	= require('https'),
	_ 		= require('underscore');

var NodeFBAuth = function(){

	return {
		initialize: function(options){
			var self = this;

			self.app_id = options.app_id;
			self.app_secret = options.app_secret;
			self.callback_url = options.callback_url || '/oauth/facebook';
			self.app = options.app
			self.base_url = options.base_url;
			self.permissions = options.permissions;

			// where to send the user after a successful OAuth redirect
			self.oauth_success_redirect = options.oauth_success_redirect || '/';

			self.fb_auth_path = options.fb_auth_path || '/auth/facebook';
			self.fb_oauth_path = options.fb_oauth_path || '/oauth/facebook';

			// --
			// -- setup some callback routes
			// --

			// GET on this address will send you to the facebook oauth dialog
			self.app.get(self.fb_auth_path, function(req, res){
				self.begin_fb_auth(req, res);
			});

			// Handle the callback from Facebook
			self.app.get(self.fb_oauth_path, function(req, res){
				self.handle_oauth_callback(req, res);
			});
		},
		build_oauth_url: function(state){
			var self = this;
			return 'https://www.facebook.com/dialog/oauth?' +
						'client_id=' + self.app_id +
						'&redirect_uri=' + encodeURIComponent(self.base_url + self.callback_url) +
						'&scope=' + self.permissions +
						'&state=' + state

		},
		build_exchange_token_url: function(code){
			var self = this;

			return { host: 'graph.facebook.com', path: '/oauth/access_token?' +
    					'client_id=' + self.app_id + 
   						'&redirect_uri=' + encodeURIComponent(self.base_url + self.callback_url) +
   						'&client_secret=' + self.app_secret + 
   						'&code=' + code };
		},
		begin_fb_auth: function(req, res){
			var self = this;

			var state = hash.md5((new Date()).getTime());

			// reset fb_auth data
			req.session.fb_auth = {};			

			req.session.fb_auth.state = state;

			// redirect to the facebook oauth entry point
			res.redirect(302, self.build_oauth_url(state));
			
		},
		// hit the graph API to grab some user data
		fetch_fb_user_details: function(access_token, callback){
			var self = this;

			var options = {
				host: 'graph.facebook.com',
				port: 443,
				path: '/me?access_token=' + access_token,
				method: 'GET'
			};

			var request = https.request(options, function(https_res){
				https_res.on('data', function(data){
					data = data.toString();

					if(https_res.statusCode == 200){
						try {
							return callback(null, JSON.parse(data));
						} catch(e){
							return callback(true, null);
						}
					} else {
						return callback(true, null);
					}
				});
			});
			request.end();

			request.on('error', function(e){
				return callback(true, null);
			});
		},
		handle_oauth_callback: function(req, res){
			var self = this;

			if('state' in req.query && 'code' in req.query){

				var state = req.query.state;
				var code = req.query.code;
				
				if(req.session.fb_auth.state && state === req.session.fb_auth.state){
					delete req.session.fb_auth.state;

					var url = self.build_exchange_token_url(code);

					var options = {
						host: url.host,
						port: 443,
						path: url.path,
						method: 'GET'
					};

					// take the code returned and upgrade to a full access token
					var request = https.request(options, function(https_res){

						https_res.on('data', function(data){
							if(https_res.statusCode == 200){
								data = data.toString().split('&');

								var fb_data = {};

								// data will contain access_toke=token&expires=timestamp in string form
								_.each(data, function(d){
									d = d.split('=');
									fb_data[d[0]] = d[1];
								});

								req.session.fb_auth = _.extend(req.session.fb_auth, fb_data);
								req.session.fb_auth.authed = true;

								self.fetch_fb_user_details(req.session.fb_auth.access_token, function(err, user){
									
									if(err === null){
										req.session.fb_auth.user = user;
									}

									return res.redirect('/');
								});
							} else {
								req.session.fb_auth.authed = false;
								return res.redirect('/');
							}							
						});
					});
					request.end();

					request.on('error', function(e){
						req.session.fb_auth.authed = false;
					});
				} else {
					return res.send(500, 'States do not match');
				}
			} else {
				// user probably declined authorization
				req.session.fb_auth = _.extend(req.session.fb_auth, req.query, { authed: false });

				res.redirect('/');
			}
		}
	}

};

module.exports = NodeFBAuth;