# A one-file Django app behind gunicorn. Django writes "Unauthorized: /auth/login" for each 401 by itself.
import json
import logging

from django.conf import settings
from django.http import JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

settings.configure(DEBUG=False, ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"], SECRET_KEY="lab-only-not-secret",
                   MIDDLEWARE=[])
logger = logging.getLogger("auth")


@csrf_exempt
def login(request):
    body = json.loads(request.body or b"{}")
    if body.get("username") == "alice" and body.get("password") == "Summer2026!":
        return JsonResponse({"token": "t"})
    logger.warning("Failed login for %s from %s", body.get("username"), request.META.get("REMOTE_ADDR"))
    return JsonResponse({"error": "invalid credentials"}, status=401)


def items(request):
    item = request.GET.get("id", "")
    if "'" in item:
        logger.error('psycopg.errors.SyntaxError: syntax error at or near "%s"', item)
        return JsonResponse({"error": "server error"}, status=500)
    return JsonResponse([], safe=False)


urlpatterns = [path("auth/login", login), path("api/items", items)]

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()
