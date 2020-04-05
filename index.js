let appConfig = {},
	jwt = {};

module.exports = function (config) {
	// Initialize opts in case it isn't passed in
	config = config || {};

	// Get default data from files, otherwise initialize empty objects
	let settings = {},
		constants = {};

	// If config contains a setting property, then merge that setting property with the default settings
	// This allows us to override the default settings with our own settings.
	// The merge deals with conflicts by using the values from config.
	if (config.hasOwnProperty('settings')) {
		Object.assign(settings, config.settings);
	}

	// This works exactly the same way as settings
	if (config.hasOwnProperty('constants')) {
		Object.assign(constants, config.constants);
	}

	config.settings = settings;
	config.constants = constants;

	// if a configuration was passed in then pass that over to the application_configuration
	appConfig = require('application-configuration')(config);

	jwt = require('./lib/jwt.js')(appConfig);

	return {
		jwt: jwt
	};
} 
