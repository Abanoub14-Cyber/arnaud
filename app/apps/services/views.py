from django.views.generic import TemplateView


class ServicesIndexView(TemplateView):
    template_name = "pages/services/index.html"


class CyberView(TemplateView):
    template_name = "pages/services/cybersecurite.html"


class WebView(TemplateView):
    template_name = "pages/services/web.html"


class IAView(TemplateView):
    template_name = "pages/services/ia_automation.html"


class SupportView(TemplateView):
    template_name = "pages/services/support.html"
