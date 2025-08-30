FROM php:8.2-apache

# Enable mysqli and pdo_mysql
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy app to Apache root
COPY . /var/www/html/

# Expose port
EXPOSE 80
