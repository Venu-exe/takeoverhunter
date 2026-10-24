"""Fingerprint database of takeover-prone services."""
SERVICES = [
    ("GitHub Pages", [".github.io", "github.io"], ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"], "Create repo named <user>.github.io or CNAME file."),
    ("Heroku", [".herokuapp.com", ".herokussl.com", "heroku.com"], ["No such app", "herokucdn.com/error-pages/no-such-app.html", "There's nothing here, yet."], "Create Heroku app with matching name."),
    ("AWS S3", [".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"], ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"], "Create S3 bucket with matching name."),
    ("Shopify", [".myshopify.com"], ["Sorry, this shop is currently unavailable", "Only one shop per domain"], "Claim shop name."),
    ("Azure Web Apps", [".azurewebsites.net"], ["404 Web Site not found", "Error 404 - Web app not found"], "Create Azure web app."),
    ("Fastly", [".fastly.net"], ["Fastly error: unknown domain", "Please check that this domain has been added to a service"], "Add domain to Fastly service."),
    ("Tumblr", [".tumblr.com"], ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"], "Claim Tumblr blog."),
    ("WordPress.com", [".wordpress.com"], ["Do you want to register", "doesn't exist", "is no longer available"], "Register WordPress site."),
    ("Ghost", [".ghost.io"], ["The thing you were looking for is no longer here"], "Claim Ghost publication."),
    ("Pantheon", [".pantheonsite.io"], ["The gods are wise", "404 error unknown site", "No site configured"], "Claim Pantheon site."),
    ("Zendesk", [".zendesk.com"], ["Help Center Closed", "Oops, this help center no longer exists"], "Claim Zendesk subdomain."),
    ("UserVoice", [".uservoice.com"], ["This UserVoice subdomain is currently available"], "Claim UserVoice portal."),
    ("Surge.sh", [".surge.sh"], ["project not found"], "surge deploy."),
    ("Bitbucket", [".bitbucket.io"], ["Repository not found"], "Create Bitbucket repo."),
    ("Webflow", [".webflow.io"], ["The page you are looking for doesn't exist or has been moved"], "Claim Webflow site."),
    ("Netlify", [".netlify.app", ".netlify.com"], ["Not Found - Request ID", "Page not found"], "Claim Netlify site."),
    ("Vercel", [".vercel.app"], ["The deployment could not be found", "404: NOT_FOUND", "DEPLOYMENT_NOT_FOUND"], "Claim Vercel project."),
    ("Readme.io", [".readme.io"], ["Project not found"], "Claim Readme project."),
    ("Cargo", [".cargocollective.com"], ["404 Not Found"], "Claim Cargo site."),
    ("Statuspage", [".statuspage.io"], ["Status page not found", "You are being redirected"], "Claim Statuspage."),
    ("HelpScout", [".helpscoutdocs.com"], ["No settings were found for this company"], "Claim HelpScout mailbox."),
    ("HelpJuice", [".helpjuice.com"], ["We could not find what you're looking for"], "Claim HelpJuice KB."),
    ("Intercom", [".intercom.io"], ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"], "Claim Intercom."),
    ("Tilda", [".tilda.ws"], ["Please renew your subscription"], "Claim Tilda site."),
    ("Smartling", [".smartling.com"], ["Domain is not configured"], "Claim Smartling project."),
    ("Acquia", [".acquia-sites.com"], ["The site you are looking for could not be found"], "Claim Acquia site."),
    ("Proposify", [".proposify.biz"], ["If you need immediate assistance"], "Claim Proposify."),
    ("Simplebooklet", [".simplebooklet.com"], ["We can't find this SimpleBooklet"], "Claim Simplebooklet."),
    ("GetResponse", [".getresponse.com"], ["Oops, something went wrong"], "Claim GetResponse."),
    ("Tictail", [".tictail.com"], ["Start selling on Tictail", "to target URL"], "Claim Tictail store."),
    ("Campaign Monitor", [".createsend.com"], ["Trying to access your account?"], "Claim Campaign Monitor."),
    ("Unbounce", [".unbounce.com"], ["The requested URL was not found on this server"], "Claim Unbounce page."),
    ("Strikingly", [".strikingly.com"], ["But if you're looking to build a stunning website"], "Claim Strikingly site."),
    ("LaunchRock", [".launchrock.com"], ["It looks like you may have taken a wrong turn"], "Claim LaunchRock."),
    ("Aftership", [".aftership.com"], ["Oops. The page you're looking for doesn't exist"], "Claim Aftership."),
    ("Pingdom", [".pingdom.com"], ["Sorry, we couldn't find the status page"], "Claim Pingdom status page."),
    ("Tave", [".tave.com"], ["Sorry, this page is no longer available"], "Claim Tave."),
    ("Formstack", [".formstack.com"], ["Oops! This page is no longer available"], "Claim Formstack."),
    ("JetBrains", [".myjetbrains.com"], ["is not a registered InCloud YouTrack"], "Claim JetBrains."),
    ("Freshdesk", [".freshdesk.com"], ["There is no helpdesk here"], "Claim Freshdesk."),
    ("Desk.com", [".desk.com"], ["Sorry, we couldn't find your site"], "Claim Desk."),
    ("CloudFront", [".cloudfront.net"], ["Bad request", "ERROR: The request could not be satisfied", "The request could not be satisfied"], "Claim CloudFront distribution (rare)."),
    ("Azure Traffic Manager", [".trafficmanager.net"], ["Page not found"], "Claim Traffic Manager profile."),
    ("AWS Elastic Beanstalk", [".elasticbeanstalk.com"], ["There is no application"], "Claim EB environment."),
    ("Fly.io", [".fly.dev"], ["404 Not Found", "app not found"], "Claim Fly app."),
    ("Render", [".onrender.com"], ["Not Found", "Service not found"], "Claim Render service."),
    ("Kinsta", [".kinsta.cloud"], ["No site configured"], "Claim Kinsta site."),
]


def match_service(cname, body, status):
    if not cname:
        return None
    cl = cname.lower()
    for svc_name, suffixes, fingerprints, note in SERVICES:
        matched_suffix = None
        for suf in suffixes:
            s = suf.lower().lstrip(".")
            if cl == s or cl.endswith("." + s) or cl.endswith(s):
                matched_suffix = suf
                break
        if not matched_suffix:
            continue
        fp_hit = None
        for fp in fingerprints:
            if fp.lower() in (body or "").lower():
                fp_hit = fp
                break
        if fp_hit:
            confidence = "high"
        elif status in (404, 403, 410, 502, 503):
            confidence = "medium"
        else:
            confidence = "low"
        return {
            "service": svc_name,
            "suffix": matched_suffix,
            "fingerprint": fp_hit,
            "note": note,
            "confidence": confidence,
        }
    return None
