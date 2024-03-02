

module.exports = function (app) {
    const expressSwagger = require('express-swagger-generator')(app)

    let options = {
        swaggerDefinition: {
            info: {
                description: 'Api for demo diamond connect',
                title: 'Diamond Connect',
                version: '1.0.0',
            },
            host: "localhost:4000",
            basePath: '/api',
            produces: [
                "application/json"
            ],
            // schemes: ['http', 'https'],
            schemes: ['http'],//
            securityDefinitions: {
                Admin: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'x-auth-token',
                    description: "",
                },
                User: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'x-auth-token',
                    description: "",
                },
            }
        },
        basedir: __dirname, //app absolute path
        files: ['./../routers/*.js',] //Path to the API handle folder
    }
    expressSwagger(options)

}