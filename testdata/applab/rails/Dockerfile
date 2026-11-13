# A Rails 8 API in production mode: Rails writes its log to standard output, tagged with the request id.
FROM ruby:3.3
RUN gem install rails -v 8.0.1 --no-document
WORKDIR /srv
RUN rails new lab --api --minimal --skip-git --skip-active-record --skip-test --skip-bundle --skip-docker --skip-kamal --skip-thruster --skip-rubocop --skip-brakeman --skip-ci
WORKDIR /srv/lab
RUN bundle install
COPY routes.rb config/routes.rb
COPY auth_controller.rb app/controllers/auth_controller.rb
COPY items_controller.rb app/controllers/items_controller.rb
ENV RAILS_ENV=production SECRET_KEY_BASE=lab-only-not-secret-0123456789abcdef RAILS_LOG_LEVEL=info
CMD ["bin/rails", "server", "-b", "0.0.0.0", "-p", "8080"]
