# Laravel with its default logging (storage/logs/laravel.log), served by artisan.
FROM composer:2
WORKDIR /srv
RUN composer create-project --no-interaction --prefer-dist laravel/laravel lab
WORKDIR /srv/lab
COPY routes.php routes/web.php
RUN sed -i -E "s#(->withMiddleware\(function \(Middleware \\\$middleware\)(: void)? \{)#\1\n        \\\$middleware->validateCsrfTokens(except: ['auth/login']);#" bootstrap/app.php \
 && grep -q "validateCsrfTokens" bootstrap/app.php \
 && sed -i 's/^APP_DEBUG=true/APP_DEBUG=false/; s/^APP_ENV=local/APP_ENV=production/' .env
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8080"]
