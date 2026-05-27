from django.views.generic import TemplateView


class MentionsView(TemplateView):
    template_name = "pages/legal/mentions.html"


class PrivacyView(TemplateView):
    template_name = "pages/legal/privacy.html"


class TermsView(TemplateView):
    template_name = "pages/legal/terms.html"


class CookiesView(TemplateView):
    template_name = "pages/legal/cookies.html"
