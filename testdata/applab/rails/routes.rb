Rails.application.routes.draw do
  post "auth/login", to: "auth#login"
  get "api/items", to: "items#index"
end
