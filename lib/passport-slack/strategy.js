console.log('LOADING THE LOCALLY LINKED VERSION');
const { userInfo } = require('os');

/**
 * Module dependencies.
 */
var util = require('util')
, OAuth2Strategy = require('passport-oauth').OAuth2Strategy;


/**
 * `Strategy` constructor.
 *
 * The Slack authentication strategy authenticates requests by delegating
 * to Slack using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`               your Slack application's client id
 *   - `clientSecret`           your Slack application's client secret
 *   - `callbackURL`            URL to which Slack will redirect the user after granting authorization
 *   - `scope`                  array of permission scopes to request defaults to:
 *                              ['identity.basic', 'identity.email', 'identity.avatar', 'identity.team']
 *                              full set of scopes: https://api.slack.com/docs/oauth-scopes
 *
 * Examples:
 *
 *     passport.use(new SlackStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/slack/callback',
 *         scope: ['identity.basic', 'channels:read', 'chat:write:user', 'client', 'admin']
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.tokenURL = options.tokenURL || 'https://slack.com/api/oauth.access';
  options.authorizationURL = options.authorizationURL || 'https://slack.com/oauth/authorize';
  options.scope = options.scope || ['identity.basic', 'identity.email', 'identity.avatar', 'identity.team'];

  this.profileUrl = options.profileUrl || "https://slack.com/api/users.identity?token="; // requires 'identity.basic' scope
  this._team = options.team;

  var _skipUserProfile = options.skipUserProfile || false;
  options.skipUserProfile = true;

  var wrapVerify = function(_verify) {
    console.log('## WRAP VERIFY');
    return function (req, accessToken, refreshToken, params, profile, verified) {
      console.log('## WRAP VERIFY EXECUTED');
      accessToken = params.authed_user.access_token;
      // TODO - FIX THIS BECAUSE IT WILL NOT WORK WITH CONCURRENCY REQUESTS.
      //        MAYBE TRY OVERRIDING https://github.com/jaredhanson/passport-oauth2/blob/master/lib/strategy.js#L173
      self._skipUserProfile = _skipUserProfile;
      self._loadUserProfile(accessToken, function(err, profile) {
        self._skipUserProfile = !_skipUserProfile;
        return _verify(req, accessToken, refreshToken, params, profile, verified);
      });
    };
  };

  OAuth2Strategy.call(this, options, wrapVerify(verify));
  this.name = options.name || 'slack';
  var self = this;

  // warn is not enough scope
  // Details on Slack's identity scope - https://api.slack.com/methods/users.identity
  if(!this._skipUserProfile && this._scope.indexOf('identity.basic') === -1){
    console.warn("Scope 'identity.basic' is required to retrieve Slack user profile");
  }
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Slack.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Slack`
 *   - `id`               the user's ID
 *   - `displayName`      the user's full name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  // console.log('# passport-slack > userProfile');
  // console.log('accessToken:', accessToken);
  // console.log('profileUrl:', this.profileUrl);
  // var self = this;
  // this.get('https://slack.com/api/auth.test?token='+accessToken, function(err, body, res) {
  //   console.log(
  //     '# auth.test', '\n',
  //     '- err:', err, '\n',
  //     '- body:', body, '\n'
  //   );
  //   var bodyJson = JSON.parse(body);
  //   var userInfoUrl = 'https://slack.com/api/users.info?token='+accessToken+'&user='+bodyJson.user_id;
  //   console.log('userInfoUrl:', userInfoUrl);
  //   self.get(userInfoUrl, function(err, body, res) {
  //     console.log(
  //       '# users.info', '\n',
  //       '- err:', err, '\n',
  //       '- body:', body, '\n'
  //     );
  //   });
  // });

  this.get(this.profileUrl + accessToken, function (err, body, res) {
    console.log('## PASSPORT-SLACK USER PROFILE');
    console.log('accessToken:', accessToken);
    console.log('err:', err);
    console.log('body:', JSON.stringify(JSON.parse(body), 0, 2));
    if (err) {
      return done(err);
    } else {
      try {
        // var profile = JSON.parse(body);

        // if (!profile.ok) {
        //   done(profile);
        // } else {
        //   delete profile.ok;

        //   profile.provider = 'Slack';
        //   profile.id = profile.user.id;
        //   profile.displayName = profile.user.name;

        //   done(null, profile);
        // };
        var json = JSON.parse(body);

        if (!json.ok) {
          return done(json.error ? json.error : body);
        }
        else {
          var profile = {
            provider: 'Slack'
          };
          profile.id = json.user.id;
          profile.displayName = json.user.name;

          profile._raw = body;
          profile._json = json;

          // get profile._json.info (This should be in the app code)
          return done(null, profile);
        }
      } catch(e) {
        done(e);
      }
    }
  });
}

/** The default oauth2 strategy puts the access_token into Authorization: header AND query string
  * which is a violation of the RFC so lets override and not add the header and supply only the token for qs.
  */
Strategy.prototype.get = function(url, callback) {
  this._oauth2._request("GET", url, {}, "", "", callback );
};



/**
 * Return extra Slack parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};
  var team = options.team || this._team;
  if (team) {
    params.team = team;
  }
  var userScope = options.user_scope; // TODO - could also support this._user_scope
  if (typeof userScope === 'string') {
    params.user_scope = userScope;
  }
  else if (typeof userScope === 'object' && typeof userScope.length === 'number') {
    params.user_scope = userScope.join(',');
  }
  return params;
};



/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
