class ItemsController < ApplicationController
  def index
    id = params[:id].to_s
    if id.include?("'")
      Rails.logger.error("PG::SyntaxError: ERROR: syntax error at or near \"#{id}\"")
      return render(json: { error: "server error" }, status: :internal_server_error)
    end
    render json: []
  end
end
