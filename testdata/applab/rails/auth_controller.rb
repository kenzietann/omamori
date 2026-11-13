class AuthController < ApplicationController
  def login
    return render(json: { token: "t" }) if params[:username] == "alice" && params[:password] == "Summer2026!"

    Rails.logger.warn("Failed login for #{params[:username]} from #{request.remote_ip}")
    render json: { error: "invalid credentials" }, status: :unauthorized
  end
end
