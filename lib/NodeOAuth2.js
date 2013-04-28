var hash 	= require('hashlib2'),
	https 	= require('https'),
	_ 		= require('underscore');

var AuthHandler = function(network){

	this.network = network || 'facebook';

	var oauthRoutes = {
		google: {
			auth: 'https://accounts.google.com/o/oauth2/auth',
			token: {
				host: 'accounts.google.com',
				path: '/o/oauth2/token'
			}
		},
		facebook: {
			auth: 'https://www.facebook.com/dialog/oauth',
			token: {
				host: 'graph.facebook.com',
				path: '/oauth/access_token'
			}
		}
	};

	return {
		initialize: function(options){
			var self = this;

			self.app_id = options.app_id;
			self.app_secret = options.app_secret;
			self.callback_path = options.callback_path || '/oauth/' + network;
			self.app = options.app;
			self.permissions = options.permissions;

			self.base_url = options.base_url;
			
			// where to send the user after a successful OAuth redirect
			self.oauth_complete_redirect = options.oauth_complete_redirect || '/';

			// entry point for authentication redirect
			self.auth_path = options.auth_path || '/auth/' + network;

			// ------------------------------------------------------------------------
			// -- setup some callback routes
			// ------------------------------------------------------------------------

			// GET on this address will send you to the facebook oauth dialog
			self.app.get(self.auth_path, function(req, res){
				self.begin_auth(req, res);
			});

			// Handle the callback from Facebook
			self.app.get(self.callback_path, function(req, res){
				self.handle_oauth_callback(req, res);
			});
		},
		/**
  		 * 	Build the Facebook OAuth entry point URL
		 */
		build_oauth_url: function(state){
			var self = this;
			
			var url = oauthRoutes[network].auth + '?' +
						'client_id=' + self.app_id +
						'&redirect_uri=' + encodeURIComponent(self.base_url + self.callback_path) +
						'&scope=' + self.permissions +
						'&state=' + state;

			if(network == 'google'){
				url += '&response_type=code&access_type=offline'
			}

			return url;
		},
		/**
		 * 	Build the URL to request an actual access_token from an auth code
		 */
		build_exchange_token_url: function(code){
			var self = this;

			var path = oauthRoutes[network].token.path

			var extendedPath = '' +
				'&code=' + code +
				'&client_id=' + self.app_id + 
				'&client_secret=' + self.app_secret + 
				'&redirect_uri=' + self.base_url + self.callback_path;
				

			if(network == 'google'){
				extendedPath += '&grant_type=authorization_code';
			}

			if(network == 'facebook'){
				path += '?' + extendedPath;
			}

			// return in two parts as we are using the https in core
			// which requires seperate host and path elements
			return { 
				host: oauthRoutes[network].token.host, 
				path: path,
				extendedPath: extendedPath
			};
		},
		/**
		 * 	Handle the callbacks from Facebook for OAuth.
		 *
		 *  - Handle the inital callback from facebook. This will return a code & expiration on
		 *    success OR an error statement.
		 *
		 *	- Upon success, make an HTTPS request to upgrade the code to a token. This is NOT
		 *    a redirect. This is done inline.
		 *
		 * 	- On error or success, set the session hash 'network_data' with the data returned and
		 * 	  redirect the user to the '/' route.
		 */
		handle_oauth_callback: function(req, res){
			var self = this;

			if('state' in req.query && 'code' in req.query){

				var state = req.query.state;
				var code = req.query.code;
				
				if(req.session[network + '_auth'].state && state === req.session[network + '_auth'].state){
					delete req.session[network + '_auth'].state;

					var url = self.build_exchange_token_url(code);

					var options = {
						host: url.host,
						port: 443,
						path: url.path,
						method: network == 'facebook' ? 'GET' : 'POST'
					};

					if(network == 'google'){
						options.headers = {
							'Content-Type': 'application/x-www-form-urlencoded'
						};
					}

					// take the code returned and upgrade to a full access token
					var request = https.request(options, function(https_res){
						https_res.on('data', function(data){
							if(https_res.statusCode == 200){
								data = data.toString();

								var network_data = {};

								if(network == 'facebook'){
									data = data.split('&');
									// data will contain access_toke=token&expires=timestamp in string form
									_.each(data, function(d){
										d = d.split('=');
										network_data[d[0]] = d[1];
									});
								} else if(network == 'google'){
									try {
										network_data = JSON.parse(data);
									} catch(e){};
								}

								req.session[network + '_auth'] = _.extend(req.session[network + '_auth'], network_data);
								req.session[network + '_auth'].authed = true;

								if(network == 'facebook'){
									self.fetch_fb_user_details(req.session[network + '_auth'].access_token, function(err, user){
										
										if(err === null){
											req.session[network + '_auth'].user = user;
										}

										return self.complete_auth(req.session[network + '_auth'], req, res);
									});
								} else if(network == 'google'){
									var user_data = {};
									self.fetch_google_user_profile(req.session[network + '_auth'].access_token, function(err, profile){
										if(err === null){
											user_data.id = profile.id;
											user_data.name = profile.displayName;
										}

										self.fetch_google_user_email(req.session[network + '_auth'].access_token, function(err, email){
											if(err === null){
												user_data.email = email.email;
											}

											req.session[network + '_auth'].user = user_data;

											return self.complete_auth(req.session[network + '_auth'], req, res);
										});
									});
								}

							} else {
								req.session[network + '_auth'].authed = false;
								return self.complete_auth(req.session[network + '_auth'], req, res);
							}							
						});
					});

					if(network == 'google'){
						request.write(url.extendedPath);
					}

					request.end();

					request.on('error', function(e){
						req.session[network + '_auth'].authed = false;
						req.session[network + '_auth'].msg = 'ERR - token upgrade failed';
						req.session[network + '_auth'].error = e;
						return self.complete_auth(req.session[network + '_auth'], req, res);
					});

				} else {
					req.session[network + '_auth'].authed = false;
					req.session[network + '_auth'].msg = 'ERR - states do not match.';
					return self.complete_auth(req.session[network + '_auth'], req, res);
				}
			} else {
				// user probably declined authorization
				req.session[network + '_auth'] = _.extend(req.session[network + '_auth'], req.query, { authed: false });
				return self.complete_auth(req.session[network + '_auth'], req, res);
			}
		},
		/**
         * 	Create a state and send the user into Facebook's OAuth flow
		 */
		begin_auth: function(req, res){
			var self = this;

			var state = hash.md5((new Date()).getTime());

			// reset auth data
			req.session[network + '_auth'] = {};			

			req.session[network + '_auth'].state = state;

			// redirect to the facebook oauth entry point
			res.redirect(302, self.build_oauth_url(state));
			
		},
		/**
		 * 	Hit the graph API for a user's info. Provides a way to test 
		 * 	a token when first getting it and to create some context.
		 */
		fetch_fb_user_details: function(access_token, callback){
			var self = this;

			var options = {
				host: 'graph.facebook.com',
				port: 443,
				path: '/me?access_token=' + access_token,
				method: 'GET'
			};

			var data = '';

			var request = https.request(options, function(https_res){
				https_res.on('data', function(chunk){
					data += chunk.toString();
				});

				https_res.on('end', function(){
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
		fetch_google_user_profile: function(access_token, callback){
			var self = this;

			var options = {
				host: 'www.googleapis.com',
				port: 443,
				path: '/plus/v1/people/me?access_token=' + access_token,
				method: 'GET'
			};

			var data = '';

			var request = https.request(options, function(https_res){
				https_res.on('data', function(chunk){
					data += chunk.toString();
				});

				https_res.on('end', function(){
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
		fetch_google_user_email: function(access_token, callback){
			var self = this;

			var options = {
				host: 'www.googleapis.com',
				port: 443,
				path: '/oauth2/v3/userinfo?access_token=' + access_token,
				method: 'GET'
			};

			var data = '';

			var request = https.request(options, function(https_res){
				https_res.on('data', function(chunk){
					data += chunk.toString();
				});

				https_res.on('end', function(){
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
		/**
		 * Complete the process by either executing the callback
		 * or redirecting to a provided route
		 */
		complete_auth: function(auth_data, req, res){
			var self = this;

			if(typeof self.oauth_complete_redirect === 'function'){
				self.oauth_complete_redirect(auth_data, req, res);
			} else {
				res.redirect(302, self.oauth_complete_redirect);
			}
		}
	}
};

var NodeOAuth2 = {
	createHandler: function(network){
		return new AuthHandler(network);
	},
	AuthHandler: AuthHandler
};

module.exports = NodeOAuth2;
