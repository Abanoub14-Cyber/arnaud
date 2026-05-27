"""Catalogue of every finding the scanner can emit.

Each slug maps to three pieces of text:

* ``title`` — short, neutral statement of what was found.
* ``summary_plain`` — one sentence in plain French aimed at a SME owner,
  explaining why this matters for their business.
* ``fix_text`` — concrete remediation, including config snippets when
  appropriate. Empty for ``pass`` findings.

All strings go through ``gettext_lazy`` so ``makemessages`` picks them up
into the .po file. The catalogue is a flat dict so the lookup at render
time is O(1).

Adding a new module: append entries here, then reference the slugs from
the module's ``CheckResult.title_key`` / ``fix_key``. The template falls
back gracefully if a slug is missing.
"""
from __future__ import annotations

from django.utils.translation import gettext_lazy as _


FINDINGS: dict[str, dict] = {

    # ----- DNS basics -----
    "dns.resolves": {
        "title": _("Le domaine répond bien"),
        "summary_plain": _("Votre site est joignable depuis Internet."),
        "fix_text": "",
    },
    "dns.no_records": {
        "title": _("Aucune adresse IP trouvée"),
        "summary_plain": _("Personne ne peut joindre votre site, ni par IPv4 ni par IPv6."),
        "fix_text": _("Ajoutez un enregistrement A (IPv4) sur votre domaine. Vérifiez que votre hébergeur a bien publié les DNS."),
    },
    "dns.no_ipv6": {
        "title": _("Pas d'IPv6 publié"),
        "summary_plain": _("Les visiteurs sur réseau IPv6-only doivent passer par une translation NAT64, ce qui ralentit l'accès."),
        "fix_text": _("Ajoutez un enregistrement AAAA pointant vers l'IPv6 de votre serveur. La plupart des hébergeurs en fournissent une gratuitement."),
    },
    "dns.has_mx": {
        "title": _("Serveur de mail configuré"),
        "summary_plain": _("Votre domaine peut recevoir des emails."),
        "fix_text": "",
    },
    "dns.no_mx": {
        "title": _("Aucun serveur de mail configuré"),
        "summary_plain": _("Aucun email envoyé à @votredomaine n'arrivera nulle part."),
        "fix_text": _("Si c'est volontaire (domaine de site vitrine seulement), vous pouvez ignorer. Sinon, ajoutez un enregistrement MX pointant vers votre fournisseur (Google Workspace, Microsoft 365, OVH, etc.)."),
    },
    "dns.has_caa": {
        "title": _("Restriction CAA en place"),
        "summary_plain": _("Seules les autorités de certification que vous avez listées peuvent émettre un certificat HTTPS pour votre domaine."),
        "fix_text": "",
    },
    "dns.no_caa": {
        "title": _("Aucune restriction CAA"),
        "summary_plain": _("N'importe quelle autorité de certification dans le monde peut émettre un certificat valide pour votre domaine, ce qui élargit la surface d'attaque."),
        "fix_text": _("Ajoutez un enregistrement CAA listant les CA autorisées. Exemple pour Let's Encrypt : 0 issue \"letsencrypt.org\""),
    },
    "dns.no_public_ip": {
        "title": _("Le domaine ne pointe vers aucune IP publique"),
        "summary_plain": _("Le domaine n'est pas joignable, ou pointe vers une adresse interne (réseau privé)."),
        "fix_text": _("Vérifiez vos enregistrements A/AAAA, et qu'ils ne pointent pas par erreur vers une IP en 10.x, 172.16-31.x ou 192.168.x."),
    },

    # ----- SPF (Sender Policy Framework) -----
    "spf.found": {
        "title": _("SPF présent"),
        "summary_plain": _("Vous déclarez officiellement quels serveurs ont le droit d'envoyer des emails à votre nom."),
        "fix_text": "",
    },
    "spf.missing": {
        "title": _("Aucun enregistrement SPF"),
        "summary_plain": _("N'importe qui sur Internet peut envoyer un email en se faisant passer pour vous. Vos clients peuvent recevoir des fausses factures à votre nom."),
        "fix_text": _("Ajoutez un enregistrement TXT à votre domaine. Pour Google Workspace par exemple : v=spf1 include:_spf.google.com -all"),
    },
    "spf.multiple": {
        "title": _("Plusieurs enregistrements SPF"),
        "summary_plain": _("Avoir plusieurs SPF rend la règle invalide, comme si aucun n'existait. Les serveurs receveurs ignoreront tout."),
        "fix_text": _("Fusionnez tous vos enregistrements SPF en un seul. Concaténez les mécanismes include: et terminez par -all."),
    },
    "spf.policy_strict": {
        "title": _("Politique SPF stricte (-all)"),
        "summary_plain": _("Les emails non autorisés sont rejetés directement. C'est la configuration recommandée."),
        "fix_text": "",
    },
    "spf.policy_soft": {
        "title": _("Politique SPF molle (~all)"),
        "summary_plain": _("Les emails frauduleux passent en spam au lieu d'être bloqués, ce qui laisse une chance qu'ils arrivent dans la boîte du destinataire."),
        "fix_text": _("Quand vous êtes sûr de votre configuration, remplacez ~all par -all à la fin de votre enregistrement SPF."),
    },
    "spf.policy_neutral": {
        "title": _("Politique SPF neutre (?all)"),
        "summary_plain": _("Vos emails légitimes ne sont pas mieux notés que les spoofés. Le SPF ne sert quasiment à rien."),
        "fix_text": _("Remplacez ?all par -all (strict) ou ~all (transition). Le ?all désactive de fait la protection."),
    },
    "spf.policy_pass_all": {
        "title": _("Politique SPF totalement permissive (+all)"),
        "summary_plain": _("Vous autorisez le monde entier à envoyer en votre nom. C'est pire que pas de SPF du tout."),
        "fix_text": _("Remplacez immédiatement +all par -all. Le +all est presque toujours une erreur de configuration."),
    },
    "spf.policy_missing": {
        "title": _("SPF sans qualificateur final"),
        "summary_plain": _("Sans -all/~all/?all à la fin, les serveurs receveurs ne savent pas comment traiter les emails non listés."),
        "fix_text": _("Ajoutez -all à la fin de votre enregistrement SPF."),
    },
    "spf.too_many_lookups": {
        "title": _("Trop de requêtes DNS dans le SPF"),
        "summary_plain": _("Le standard limite à 10 le nombre de mécanismes nécessitant une requête DNS. Au-delà, votre SPF est invalide."),
        "fix_text": _("Aplatissez votre SPF (remplacez les include: par les IP réelles), ou utilisez un service de SPF flattening."),
    },

    # ----- DMARC -----
    "dmarc.found": {
        "title": _("DMARC présent"),
        "summary_plain": _("Vous avez une politique anti-usurpation pour votre domaine."),
        "fix_text": "",
    },
    "dmarc.missing": {
        "title": _("Aucun enregistrement DMARC"),
        "summary_plain": _("Sans DMARC, même avec SPF en place, les serveurs receveurs n'ont aucune politique claire pour traiter les tentatives de spoofing."),
        "fix_text": _("Ajoutez un TXT sur _dmarc.votredomaine.be. Commencez en monitor : v=DMARC1; p=none; rua=mailto:vous@votredomaine.be. Surveillez quelques semaines puis durcissez."),
    },
    "dmarc.multiple": {
        "title": _("Plusieurs enregistrements DMARC"),
        "summary_plain": _("Avoir plusieurs DMARC rend la politique invalide, comme si aucune n'existait."),
        "fix_text": _("Fusionnez tous vos enregistrements DMARC en un seul TXT sur _dmarc.votredomaine.be."),
    },
    "dmarc.policy_reject": {
        "title": _("Politique DMARC stricte (p=reject)"),
        "summary_plain": _("Les emails frauduleux sont rejetés directement. C'est la configuration cible."),
        "fix_text": "",
    },
    "dmarc.policy_quarantine": {
        "title": _("Politique DMARC en quarantaine (p=quarantine)"),
        "summary_plain": _("Les emails frauduleux sont mis en spam mais pas rejetés. Une partie peut quand même être lue par le destinataire."),
        "fix_text": _("Quand vous êtes sûr que tous vos flux légitimes passent, faites évoluer p=quarantine vers p=reject."),
    },
    "dmarc.policy_none": {
        "title": _("DMARC en mode monitor (p=none)"),
        "summary_plain": _("Vous recevez des rapports mais aucun email frauduleux n'est bloqué. Les attaquants peuvent toujours se faire passer pour vous."),
        "fix_text": _("Une fois que vos rapports DMARC montrent que vos flux légitimes passent (en général après 2 à 4 semaines), passez en p=quarantine puis p=reject."),
    },
    "dmarc.policy_invalid": {
        "title": _("Politique DMARC invalide"),
        "summary_plain": _("La valeur du tag p= n'est pas reconnue. Votre DMARC est ignoré par les serveurs receveurs."),
        "fix_text": _("Le tag p= doit valoir none, quarantine ou reject. Corrigez la valeur dans votre TXT _dmarc."),
    },
    "dmarc.subpolicy_none": {
        "title": _("Sous-domaines non protégés (sp=none)"),
        "summary_plain": _("Votre politique DMARC ne protège pas les sous-domaines comme support.votredomaine ou facture.votredomaine. Un attaquant peut spoofer ceux-ci."),
        "fix_text": _("Retirez le tag sp=none ou alignez-le sur p (par exemple sp=reject) pour étendre la protection à tous vos sous-domaines."),
    },
    "dmarc.no_rua": {
        "title": _("Aucune adresse de rapports DMARC"),
        "summary_plain": _("Sans rua=, vous ne saurez jamais qui essaie d'usurper votre domaine. Vous êtes aveugle aux tentatives."),
        "fix_text": _("Ajoutez rua=mailto:dmarc@votredomaine.be à votre TXT _dmarc. Vous recevrez des rapports XML résumant les tentatives."),
    },

    # ----- TLS / certificats -----
    "tls.handshake_ok": {
        "title": _("Connexion HTTPS valide"),
        "summary_plain": _("Le certificat est correct et la chaîne de confiance se vérifie."),
        "fix_text": "",
    },
    "tls.no_target": {
        "title": _("Impossible de tester HTTPS"),
        "summary_plain": _("Pas d'IP publique trouvée pour ouvrir une connexion TLS."),
        "fix_text": "",
    },
    "tls.invalid_chain": {
        "title": _("Chaîne de certification invalide"),
        "summary_plain": _("Les navigateurs afficheront un avertissement rouge à vos visiteurs. La plupart partiront immédiatement."),
        "fix_text": _("Vérifiez que votre certificat inclut tous les certificats intermédiaires. Renouvelez via Let's Encrypt si vous utilisez certbot, ou corrigez la configuration dans votre reverse proxy."),
    },
    "tls.connection_failed": {
        "title": _("Connexion HTTPS impossible"),
        "summary_plain": _("Votre site n'a pas pu être joint en HTTPS, ou le serveur ne répond pas sur le port 443."),
        "fix_text": _("Vérifiez que votre serveur écoute bien sur le port 443 et que le firewall (Cloudflare, Traefik, etc.) le laisse passer."),
    },
    "tls.no_cert": {
        "title": _("Aucun certificat retourné"),
        "summary_plain": _("Le serveur a accepté la connexion TLS mais n'a pas envoyé de certificat. Configuration cassée."),
        "fix_text": _("Vérifiez la configuration TLS de votre serveur ou de votre reverse proxy."),
    },
    "tls.expired": {
        "title": _("Certificat HTTPS expiré"),
        "summary_plain": _("Tout visiteur voit un avertissement de sécurité rouge. C'est probablement votre plus gros problème actuel."),
        "fix_text": _("Renouvelez immédiatement votre certificat. Si vous utilisez Let's Encrypt, vérifiez le renouvellement automatique (certbot renew)."),
    },
    "tls.expiring_soon": {
        "title": _("Certificat HTTPS expire dans moins de 14 jours"),
        "summary_plain": _("Si rien n'est fait, votre site sera bientôt indisponible. Le renouvellement automatique a peut-être échoué."),
        "fix_text": _("Forcez un renouvellement maintenant et vérifiez que votre cron de renouvellement fonctionne."),
    },
    "tls.expiring_soonish": {
        "title": _("Certificat HTTPS expire dans moins de 30 jours"),
        "summary_plain": _("Votre certificat va bientôt arriver à échéance. Le renouvellement devrait normalement déjà être planifié."),
        "fix_text": _("Confirmez que votre renouvellement automatique fonctionne. La fenêtre de renouvellement Let's Encrypt commence à 30 jours avant expiration."),
    },
    "tls.expiry_ok": {
        "title": _("Certificat HTTPS valide longtemps"),
        "summary_plain": _("Votre certificat est valide pour plusieurs semaines."),
        "fix_text": "",
    },
    "tls.san_mismatch": {
        "title": _("Certificat sur le mauvais domaine"),
        "summary_plain": _("Le certificat ne couvre pas votre domaine. Les navigateurs afficheront un avertissement de sécurité."),
        "fix_text": _("Émettez un nouveau certificat couvrant le domaine, ou configurez votre serveur pour utiliser le bon certificat (SNI)."),
    },

    # ----- HTTP headers -----
    "headers.fetched": {
        "title": _("Site accessible en HTTPS"),
        "summary_plain": _("Le scanner a pu récupérer la page d'accueil pour analyser les en-têtes."),
        "fix_text": "",
    },
    "headers.no_target": {
        "title": _("Impossible de récupérer les en-têtes"),
        "summary_plain": _("Pas d'IP publique trouvée."),
        "fix_text": "",
    },
    "headers.fetch_failed": {
        "title": _("La page d'accueil n'a pas répondu"),
        "summary_plain": _("Le scanner n'a pas pu récupérer https://votredomaine/ : timeout ou erreur réseau."),
        "fix_text": _("Vérifiez que votre site est joignable en HTTPS depuis l'extérieur."),
    },
    "headers.no_hsts": {
        "title": _("HSTS absent"),
        "summary_plain": _("Un attaquant sur le réseau peut intercepter la première visite et rediriger vers une copie pirate de votre site."),
        "fix_text": _("Ajoutez l'en-tête Strict-Transport-Security: max-age=31536000; includeSubDomains à toutes vos réponses HTTPS."),
    },
    "headers.hsts_short": {
        "title": _("Durée HSTS trop courte"),
        "summary_plain": _("Le navigateur oubliera trop vite que votre site impose HTTPS. Recommandé : au moins 6 mois."),
        "fix_text": _("Augmentez max-age à 31536000 (1 an) ou 63072000 (2 ans). Une fois testé, ajoutez preload."),
    },
    "headers.hsts_ok": {
        "title": _("HSTS bien configuré"),
        "summary_plain": _("Les navigateurs forcent l'HTTPS pour votre domaine pendant une durée suffisante."),
        "fix_text": "",
    },
    "headers.no_csp": {
        "title": _("Aucune Content Security Policy"),
        "summary_plain": _("En cas de faille XSS, l'attaquant peut exécuter n'importe quel script dans le navigateur de vos visiteurs sans contrainte."),
        "fix_text": _("Ajoutez une CSP. Pour un site classique : default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'. Adaptez à vos besoins réels."),
    },
    "headers.csp_ok": {
        "title": _("Content Security Policy en place"),
        "summary_plain": _("Vous limitez ce que peut faire un script malveillant injecté dans la page."),
        "fix_text": "",
    },
    "headers.no_clickjacking": {
        "title": _("Protection anti-clickjacking absente"),
        "summary_plain": _("Votre site peut être affiché dans une iframe sur un autre site, qui peut faire croire à vos visiteurs qu'ils cliquent sur autre chose."),
        "fix_text": _("Ajoutez l'en-tête X-Frame-Options: DENY (ou SAMEORIGIN) ou la directive CSP frame-ancestors 'self'."),
    },
    "headers.no_nosniff": {
        "title": _("X-Content-Type-Options manquant"),
        "summary_plain": _("Les navigateurs peuvent deviner le type d'un fichier et exécuter du code dans un contexte inattendu."),
        "fix_text": _("Ajoutez l'en-tête X-Content-Type-Options: nosniff sur toutes vos réponses."),
    },
    "headers.no_referrer_policy": {
        "title": _("Referrer-Policy non définie"),
        "summary_plain": _("Le navigateur peut transmettre l'URL complète de votre site (avec ses paramètres) aux sites externes que vos pages référencent."),
        "fix_text": _("Ajoutez Referrer-Policy: strict-origin-when-cross-origin. C'est un bon défaut pour la plupart des sites."),
    },
    "headers.server_version_leak": {
        "title": _("La version du serveur web est exposée"),
        "summary_plain": _("Un attaquant qui scanne le web automatiquement peut cibler les vulnérabilités connues de votre version exacte."),
        "fix_text": _("Cachez ou simplifiez l'en-tête Server. Sous nginx : server_tokens off. Sous Apache : ServerTokens Prod."),
    },
    "headers.no_permissions_policy": {
        "title": _("Permissions-Policy absent"),
        "summary_plain": _("Vous n'avez pas restreint l'accès aux API sensibles du navigateur (caméra, micro, géolocalisation). Une faille XSS pourrait abuser de ces capacités."),
        "fix_text": _("Ajoutez Permissions-Policy: camera=(), microphone=(), geolocation=(). Activez seulement les fonctionnalités dont vous avez vraiment besoin."),
    },
    "headers.no_coop": {
        "title": _("Cross-Origin-Opener-Policy absent"),
        "summary_plain": _("Sans COOP, une fenêtre ouverte par votre site peut accéder à votre contexte d'origine, ouvrant la porte à des attaques de type Spectre."),
        "fix_text": _("Ajoutez Cross-Origin-Opener-Policy: same-origin (le plus strict) ou same-origin-allow-popups si vous utilisez OAuth ou des popups tiers."),
    },
    "headers.no_coep": {
        "title": _("Cross-Origin-Embedder-Policy absent"),
        "summary_plain": _("Optionnel pour la plupart des sites. Requis uniquement si vous voulez activer l'isolation cross-origin pour SharedArrayBuffer ou WebAssembly threads."),
        "fix_text": _("Si vous n'utilisez pas SharedArrayBuffer, vous pouvez ignorer. Sinon : Cross-Origin-Embedder-Policy: require-corp."),
    },
    "headers.no_corp": {
        "title": _("Cross-Origin-Resource-Policy absent"),
        "summary_plain": _("Sans CORP, vos ressources peuvent être embarquées par n'importe quel site. C'est rarement critique mais c'est un défaut moderne."),
        "fix_text": _("Ajoutez Cross-Origin-Resource-Policy: same-site sur les réponses qui ne doivent pas être consommées ailleurs."),
    },

    # ----- DKIM -----
    "dkim.found": {
        "title": _("DKIM configuré"),
        "summary_plain": _("Vos emails sont signés cryptographiquement, ce qui empêche un attaquant de forger des messages crédibles à votre nom."),
        "fix_text": "",
    },
    "dkim.skipped_no_mx": {
        "title": _("DKIM non vérifié (pas de MX)"),
        "summary_plain": _("Le domaine ne reçoit pas d'email, donc DKIM n'est pas applicable."),
        "fix_text": "",
    },
    "dkim.none_common": {
        "title": _("DKIM non détecté sur les sélecteurs testés"),
        "summary_plain": _("Aucun des sélecteurs DKIM connus que nous avons testés ne renvoie de clé publique. Soit votre domaine n'a pas DKIM, soit il utilise un sélecteur non-standard (Mailcow, Postfix custom, etc.) que nous ne pouvons pas deviner depuis le DNS seul."),
        "fix_text": _("Activez DKIM chez votre fournisseur email (Google Workspace, Microsoft 365, OVH, etc.). Vous obtiendrez un sélecteur et une clé publique à publier en TXT dans votre zone DNS. Sans DKIM, vos emails sont plus facilement marqués comme spam."),
    },

    # ----- DNSSEC -----
    "dnssec.signed": {
        "title": _("DNSSEC actif"),
        "summary_plain": _("Vos enregistrements DNS sont signés, un attaquant ne peut pas insérer de réponses falsifiées."),
        "fix_text": "",
    },
    "dnssec.partial": {
        "title": _("DNSSEC incomplet"),
        "summary_plain": _("La signature DNSSEC est présente mais la chaîne de confiance avec votre registre est cassée. La protection ne s'applique pas."),
        "fix_text": _("Vérifiez que les enregistrements DS au niveau de votre registre (par exemple DNS Belgium pour les .be) correspondent bien aux DNSKEY publiés."),
    },
    "dnssec.unsigned": {
        "title": _("DNSSEC non activé"),
        "summary_plain": _("Sans DNSSEC, un attaquant qui contrôle un résolveur DNS peut rediriger vos visiteurs vers un site pirate."),
        "fix_text": _("La plupart des hébergeurs DNS proposent l'activation DNSSEC en un clic. C'est gratuit et n'a aucun impact sur les visiteurs."),
    },

    # ----- HTTP redirect -----
    "redirect.no_target": {
        "title": _("Redirection HTTP non vérifiable"),
        "summary_plain": _("Pas d'IP publique pour tester."),
        "fix_text": "",
    },
    "redirect.no_http": {
        "title": _("Port 80 fermé"),
        "summary_plain": _("Le serveur ne répond pas en HTTP. C'est correct du point de vue sécurité, mais les visiteurs qui tapent l'URL sans https obtiendront une erreur de connexion."),
        "fix_text": _("Idéalement, ouvrez le port 80 et faites une redirection 301 permanente vers HTTPS. Cela améliore l'expérience visiteur sans dégrader la sécurité."),
    },
    "redirect.serves_http": {
        "title": _("Le site répond en HTTP non chiffré"),
        "summary_plain": _("Vos visiteurs peuvent recevoir le site en clair. Un attaquant sur le réseau peut lire et modifier le contenu en route."),
        "fix_text": _("Configurez votre serveur (ou Cloudflare, Traefik, etc.) pour rediriger toutes les requêtes HTTP vers HTTPS avec un code 301."),
    },
    "redirect.target_not_https": {
        "title": _("La redirection ne pointe pas vers HTTPS"),
        "summary_plain": _("Le serveur redirige les visiteurs ailleurs qu'en HTTPS. La connexion reste vulnérable."),
        "fix_text": _("Corrigez la cible de la redirection pour qu'elle commence par https://. Vérifiez la configuration de votre reverse proxy."),
    },
    "redirect.permanent_https": {
        "title": _("Redirection 301 vers HTTPS"),
        "summary_plain": _("Les visiteurs qui tapent l'URL sans https arrivent sur la version sécurisée, et leurs navigateurs mémorisent la redirection."),
        "fix_text": "",
    },
    "redirect.temporary_only": {
        "title": _("Redirection 302 temporaire vers HTTPS"),
        "summary_plain": _("La redirection fonctionne mais le navigateur ne la met pas en cache. C'est moins efficace pour le SEO et le HSTS preload."),
        "fix_text": _("Changez le code de redirection en 301 (permanente) au lieu de 302/307."),
    },

    # ----- Domain breach -----
    "breach.none": {
        "title": _("Aucune fuite publique connue"),
        "summary_plain": _("Aucune base de données piratée publiquement répertoriée ne mentionne votre domaine."),
        "fix_text": "",
    },
    "breach.recent": {
        "title": _("Fuite récente impliquant votre domaine"),
        "summary_plain": _("Votre domaine apparaît dans une fuite divulguée publiquement il y a moins d'un an. Vos employés et clients ont peut-être des credentials compromis circulant."),
        "fix_text": _("Forcez une rotation des mots de passe. Activez le MFA partout où c'est possible. Surveillez les tentatives de connexion suspectes pendant les 6 prochains mois."),
    },
    "breach.medium": {
        "title": _("Fuite des 3 dernières années impliquant votre domaine"),
        "summary_plain": _("Votre domaine apparaît dans une fuite récente. Les credentials compromis y circulent peut-être encore."),
        "fix_text": _("Si vous n'avez pas forcé de rotation des mots de passe depuis cette fuite, faites-le. Activez le MFA sur les comptes critiques."),
    },
    "breach.old": {
        "title": _("Fuite ancienne impliquant votre domaine"),
        "summary_plain": _("Votre domaine apparaît dans des bases divulguées publiquement il y a plus de 3 ans. À surveiller mais pas urgent si vos mots de passe ont été tournés depuis."),
        "fix_text": _("Vérifiez que vos employés n'utilisent plus les mots de passe qui ont fuité. Sensibilisez sur le credential stuffing."),
    },
    "breach.api_unavailable": {
        "title": _("Vérification HIBP indisponible"),
        "summary_plain": _("Le service Have I Been Pwned n'a pas répondu, on n'a pas pu vérifier les fuites pour ce domaine. Réessayez dans quelques minutes."),
        "fix_text": "",
    },

    # ----- Module-level errors -----
    "module.crashed": {
        "title": _("Un module a échoué"),
        "summary_plain": _("Le scanner a rencontré une erreur sur ce contrôle. Le reste du rapport reste valide."),
        "fix_text": "",
    },

    # ----- Web checks skipped: no website to inspect -----
    "web.skipped_no_homepage": {
        "title": _("Aucun site web à analyser"),
        "summary_plain": _("Le serveur ne répond pas sur le port 443. Les contrôles web (TLS, en-têtes, redirections, cookies) sont ignorés, ils n'apportent rien quand il n'y a pas de site."),
        "fix_text": "",
    },

    # ----- Site profile (A1 + A2) -----
    "site.real": {
        "title": _("Site web actif détecté"),
        "summary_plain": _("Le serveur a répondu et la page d'accueil ressemble à un vrai site."),
        "fix_text": "",
    },
    "site.parked": {
        "title": _("Domaine parked"),
        "summary_plain": _("Le domaine n'héberge pas un vrai site. Il pointe vers une page de parking publicitaire ou une page d'attente."),
        "fix_text": _("Si ce domaine doit héberger un site, configurez votre serveur web ou retirez la délégation vers le parking."),
    },
    "site.for_sale": {
        "title": _("Domaine en vente"),
        "summary_plain": _("La page d'accueil affiche que ce domaine est mis en vente."),
        "fix_text": "",
    },
    "site.registrar_default": {
        "title": _("Page par défaut de l'hébergeur"),
        "summary_plain": _("Le serveur sert la page d'accueil par défaut (nginx, Apache, IIS, Plesk). Le site n'a pas encore été configuré."),
        "fix_text": _("Déployez votre site, ou retirez l'A/AAAA en attendant pour ne pas exposer la page par défaut."),
    },
    "site.non_html": {
        "title": _("Le serveur ne sert pas une page HTML"),
        "summary_plain": _("La home renvoie autre chose qu'une page web (souvent une API ou une réponse JSON)."),
        "fix_text": "",
    },
    "site.redirects": {
        "title": _("Le domaine redirige vers une autre URL"),
        "summary_plain": _("La page d'accueil renvoie une redirection (souvent vers la version www. ou un sous-chemin)."),
        "fix_text": "",
    },
    "site.unreachable": {
        "title": _("Site injoignable en HTTPS"),
        "summary_plain": _("Le scanner n'a pas réussi à contacter votre serveur sur le port 443. La majorité des contrôles web ne pourront pas s'effectuer."),
        "fix_text": _("Vérifiez que le serveur est en ligne et que le port 443 est ouvert. Sur Cloudflare, vérifiez que le proxy n'est pas en mode 'Under Attack'."),
    },

    # ----- Cookie security (W2) -----
    "cookies.ok": {
        "title": _("Cookies correctement protégés"),
        "summary_plain": _("Tous les cookies posés par la page d'accueil ont les flags Secure, HttpOnly et SameSite."),
        "fix_text": "",
    },
    "cookies.no_secure": {
        "title": _("Cookie sans le flag Secure"),
        "summary_plain": _("Ce cookie peut être transmis en clair sur une connexion HTTP. Un attaquant sur le réseau peut le voler."),
        "fix_text": _("Ajoutez l'attribut Secure à ce cookie. Exemple : Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax."),
    },
    "cookies.no_httponly": {
        "title": _("Cookie accessible en JavaScript"),
        "summary_plain": _("Ce cookie peut être lu par n'importe quel script de la page. En cas de XSS, il est volable."),
        "fix_text": _("Ajoutez l'attribut HttpOnly. Sauf cas particulier (consentement, langue), ce cookie n'a pas besoin d'être lu en JS."),
    },
    "cookies.no_samesite": {
        "title": _("Cookie sans SameSite"),
        "summary_plain": _("Sans SameSite, ce cookie est envoyé sur des requêtes initiées par un autre site, ce qui ouvre la porte au CSRF."),
        "fix_text": _("Ajoutez SameSite=Lax (le bon défaut), ou Strict si la session ne traverse jamais une autre origine."),
    },

    # ----- WWW variant (W1) -----
    "redirect.www_redirects": {
        "title": _("Variante www. redirige correctement"),
        "summary_plain": _("Vos visiteurs arrivent au bon endroit qu'ils tapent www ou non."),
        "fix_text": "",
    },
    "redirect.www_missing": {
        "title": _("Variante www. non configurée"),
        "summary_plain": _("Le sous-domaine www n'existe pas. Les visiteurs qui tapent www.votredomaine obtiendront une erreur."),
        "fix_text": _("Ajoutez un CNAME ou un A pour www pointant sur votre apex, et configurez la redirection 301 vers la version sans www (ou inversement)."),
    },
    "redirect.www_split_brain": {
        "title": _("Configuration en split brain entre apex et www"),
        "summary_plain": _("L'apex et www servent du contenu différent sans redirection. Vos visiteurs voient deux sites différents selon l'URL tapée."),
        "fix_text": _("Choisissez une version canonique (avec ou sans www) et redirigez l'autre en 301."),
    },
    "redirect.www_unreachable": {
        "title": _("Variante www. injoignable"),
        "summary_plain": _("Le www. résout en DNS mais ne répond pas en HTTPS."),
        "fix_text": _("Vérifiez que votre serveur écoute aussi sur www, ou retirez l'enregistrement DNS si vous ne l'utilisez pas."),
    },
    "redirect.www_other": {
        "title": _("Variante www. anormale"),
        "summary_plain": _("La variante www renvoie un statut HTTP inhabituel."),
        "fix_text": _("Vérifiez la configuration de votre serveur ou de votre reverse proxy pour le sous-domaine www."),
    },

    # ----- Email synthesis (E1) -----
    "email.synth_spoof_resistant": {
        "title": _("Domaine difficile à usurper"),
        "summary_plain": _("SPF strict, DKIM en place, DMARC en p=reject avec alignement strict. Personne ne peut envoyer un email crédible en votre nom."),
        "fix_text": "",
    },
    "email.synth_moderate": {
        "title": _("Protection email modérée"),
        "summary_plain": _("La configuration anti-usurpation est en place mais incomplète. Un attaquant peut encore réussir à passer dans certains scénarios."),
        "fix_text": _("Pour atteindre le niveau 'spoof-resistant' : SPF doit terminer par -all, DKIM doit être actif sur au moins un sélecteur, DMARC doit être en p=reject avec aspf=s et adkim=s."),
    },
    "email.synth_weak": {
        "title": _("Protection email faible"),
        "summary_plain": _("Vos protections SPF, DKIM et DMARC laissent encore passer certains scénarios d'usurpation. Voyez les findings individuels plus bas pour savoir exactement ce qui manque."),
        "fix_text": _("Étape 1 : assurez-vous d'avoir SPF (-all), DKIM (au moins un sélecteur), et DMARC. Étape 2 : surveillez vos rapports DMARC quelques semaines. Étape 3 : passez DMARC en p=quarantine puis p=reject."),
    },
    "email.synth_spoofable": {
        "title": _("Domaine usurpable"),
        "summary_plain": _("N'importe qui peut envoyer un email en se faisant passer pour @votredomaine. Vos clients risquent de recevoir des fausses factures crédibles à votre nom."),
        "fix_text": _("Action urgente : ajoutez SPF, DKIM et DMARC. Démarrez par SPF strict (-all), activez DKIM chez votre fournisseur email, puis DMARC en monitor (p=none) avant de durcir."),
    },

    # ----- RDAP (H1) -----
    "rdap.expiry_ok": {
        "title": _("Enregistrement de domaine valide"),
        "summary_plain": _("Votre domaine est enregistré pour encore plusieurs semaines."),
        "fix_text": "",
    },
    "rdap.expired": {
        "title": _("Domaine expiré"),
        "summary_plain": _("L'enregistrement de votre domaine a expiré. Il peut être racheté par n'importe qui à tout moment."),
        "fix_text": _("Renouvelez immédiatement votre domaine auprès de votre registrar. Si le rachat est déjà parti, vous risquez de perdre l'accès."),
    },
    "rdap.expiring_soon": {
        "title": _("Domaine expire dans moins de 30 jours"),
        "summary_plain": _("Si rien n'est fait, votre site sera bientôt indisponible et le domaine pourra être repris."),
        "fix_text": _("Renouvelez maintenant chez votre registrar. Activez le renouvellement automatique pour ne plus avoir le souci."),
    },
    "rdap.recently_registered": {
        "title": _("Domaine récemment enregistré"),
        "summary_plain": _("Ce domaine a été créé il y a moins de 30 jours. Pour des sites établis, c'est inhabituel et peut être un signal de phishing."),
        "fix_text": "",
    },
    "rdap.partial": {
        "title": _("Informations de domaine partielles"),
        "summary_plain": _("Le serveur RDAP a répondu mais sans dates de création ou d'expiration."),
        "fix_text": "",
    },
    "rdap.unavailable": {
        "title": _("Données de registre indisponibles"),
        "summary_plain": _("Le TLD de ce domaine ne publie pas de serveur RDAP, ou le serveur n'a pas répondu. Pas de pénalité."),
        "fix_text": "",
    },
}


CATEGORY_LABELS: dict[str, dict] = {
    "email": {
        "title": _("Sécurité email"),
        "subtitle": _("SPF, DKIM, DMARC"),
        "icon": "mail",
    },
    "web": {
        "title": _("Sécurité web"),
        "subtitle": _("Certificat HTTPS, redirections, en-têtes"),
        "icon": "shield_lock",
    },
    "hygiene": {
        "title": _("Hygiène DNS"),
        "subtitle": _("Adresses, DNSSEC, CAA"),
        "icon": "hub",
    },
    "privacy": {
        "title": _("Vie privée et fuites"),
        "subtitle": _("Bases compromises, signaux publics"),
        "icon": "policy",
    },
}


def get_category_label(slug: str) -> dict:
    return CATEGORY_LABELS.get(slug, {"title": slug, "subtitle": "", "icon": "category"})


# Module slug -> category slug. Source of truth lives on the Module class
# itself (Module.category) but mirroring it here avoids importing the whole
# scanner package in views.
MODULE_TO_CATEGORY: dict[str, str] = {
    "site_profile": "hygiene",
    "dns_basics": "hygiene",
    "dnssec": "hygiene",
    "rdap": "hygiene",
    "spf": "email",
    "dkim": "email",
    "dmarc": "email",
    "tls_cert": "web",
    "http_redirect": "web",
    "http_headers": "web",
    "breach_domain": "privacy",
}


MODULE_LABELS: dict[str, dict] = {
    "site_profile": {
        "title": _("Profil du site"),
        "subtitle": _("Type de site, stack, WAF/CDN"),
    },
    "rdap": {
        "title": _("Registre du domaine"),
        "subtitle": _("Registrar, dates de création et d'expiration"),
    },
    "dns_basics": {
        "title": _("DNS"),
        "subtitle": _("Adresses, MX, CAA"),
    },
    "dnssec": {
        "title": _("DNSSEC"),
        "subtitle": _("Signature de la zone"),
    },
    "spf": {
        "title": _("SPF"),
        "subtitle": _("Anti-spoofing email"),
    },
    "dkim": {
        "title": _("DKIM"),
        "subtitle": _("Signature des emails sortants"),
    },
    "dmarc": {
        "title": _("DMARC"),
        "subtitle": _("Politique anti-usurpation"),
    },
    "tls_cert": {
        "title": _("Certificat HTTPS"),
        "subtitle": _("Validité et chaîne de confiance"),
    },
    "http_redirect": {
        "title": _("Redirection HTTP -> HTTPS"),
        "subtitle": _("Port 80 et permanence"),
    },
    "http_headers": {
        "title": _("En-têtes HTTP"),
        "subtitle": _("HSTS, CSP, anti-clickjacking"),
    },
    "breach_domain": {
        "title": _("Fuites publiques"),
        "subtitle": _("Domaine présent dans des bases compromises"),
    },
}


def get_module_label(slug: str) -> dict:
    return MODULE_LABELS.get(slug, {"title": slug, "subtitle": ""})


def get_finding(slug: str) -> dict:
    """Look up a slug, falling back to a placeholder if unknown."""
    if not slug:
        return {"title": "", "summary_plain": "", "fix_text": ""}
    found = FINDINGS.get(slug)
    if found:
        return found
    # Defensive default — surfaces the slug so we know to add it to the catalogue.
    return {
        "title": slug.replace(".", " · "),
        "summary_plain": "",
        "fix_text": "",
    }
