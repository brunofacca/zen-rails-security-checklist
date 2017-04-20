# Zen Rails Security Checklist

## Summary
This document provides a list of security measures to be implemented when 
developing a Ruby on Rails application. It is designed to serve as a quick 
reference and minimize vulnerabilities caused by developer forgetfulness. 

This checklist is meant to be a community-driven resource. Your 
[contributions](#contributing) are welcome! 

**Disclaimer**: This document does not cover all possible security 
vulnerabilities. The authors do not take any legal responsibility for the 
accuracy or completeness of the information herein.


## Supported Rails Versions
This document focuses on Rails 4 and 5. Vulnerabilities that were present in 
earlier versions and fixed in Rails 4 are not included.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of Contents

- [Zen Rails Security Checklist](#zen-rails-security-checklist)
  - [Summary](#summary)
  - [Supported Rails Versions](#supported-rails-versions)
  - [The Checklist](#the-checklist)
      - [Injection](#injection)
      - [Authentication (Devise)](#authentication-devise)
      - [Sessions & Cookies](#sessions--cookies)
      - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
          - [Handling User Input](#handling-user-input)
      - [HTTP & TLS](#http--tls)
      - [Authorization (Pundit)](#authorization-pundit)
      - [Files](#files)
          - [File Uploads](#file-uploads)
      - [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
      - [Sensitive Data Exposure](#sensitive-data-exposure)
      - [Routing, Template Selection, and Redirection](#routing-template-selection-and-redirection)
      - [Third-party Software](#third-party-software)
      - [Security Tools](#security-tools)
      - [Others](#others)
  - [Details and Code Samples](#details-and-code-samples)
      - [Password validation regex](#password-validation-regex)
      - [Pundit: ensure all actions are authorized](#pundit-ensure-all-actions-are-authorized)
      - [Pundit: only display appropriate records in select boxes](#pundit-only-display-appropriate-records-in-select-boxes)
      - [Convert filter_parameters into a whitelist](#convert-filter_parameters-into-a-whitelist)
  - [Authors](#authors)
  - [Contributing](#contributing)
  - [References and Further Reading](#references-and-further-reading)
  - [License](#license)

  Table of contents generated with [DocToc](https://github.com/thlorenz/doctoc)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## The Checklist

#### Injection 
Injection attacks are #1 at the [OWASP Top10](https://www.owasp.org/index.php/Top_10_2013-Top_10). 
- [ ] Don’t use standard Ruby interpolation (`#{foo}`) to insert user inputted
strings into ActiveRecord or raw SQL queries. Use the `?` character, named bind
variables or the [ActiveRecord::Sanitization
methods](http://api.rubyonrails.org/classes/ActiveRecord/Sanitization/ClassMethods.html#method-i-sanitize_conditions)
to sanitize user input used in DB queries. *Mitigates SQL injection attacks.*
- [ ] Don't pass user inputted strings to methods capable of evaluating 
code or running O.S. commands such as `eval`, `system`, `syscall`, `%x()`, and 
`exec`. *Mitigates command injection attacks.*

Resources:
- [Ruby on Rails Security Guide - SQL Injection](http://guides.rubyonrails.org/security.html#sql-injection)
- [Rails SQL Injection Examples](https://rails-sqli.org/)

#### Authentication (Devise)

Broken Authentication and Session Management are #2 at the [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10).
- [ ] Enforce a minimum password length of 8 characters or more. *Mitigates
brute-force attacks.*
- [ ] Consider validating passwords against:
    - Dictionary words. Since passwords have a minimum length requirement, the
   dictionary need only include words meeting that requirement. 
   - A list of commonly used passwords such as
   [these](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
   The [password_strength](https://github.com/fnando/password_strength) and
   [StrongPassword](https://github.com/bdmac/strong_password) gems provide such
   feature.
    - A leaked password database such as [PasswordPing](https://www.passwordping.com/docs-passwords-api/).
    - Context-specific words, such as the name of the application, the
    username, and derivatives thereof.
- [ ] Consider the pros and cons of enforcing password complexity rules such as
mixtures of different character types. Most applications use it. However, the
latest [NIST Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html) advise
against it. An alternative is to increase the minimum length requirement and
encourage the usage of passphrases. Devise only validates password length. Gems
such as
[devise_security_extension](https://github.com/phatworx/devise_security_extension),
[StrongPassword](https://github.com/bdmac/strong_password),
[devise_zxcvbn](https://github.com/bitzesty/devise_zxcvbn), and
[password_strength](https://github.com/fnando/password_strength) provide
additional password validation capabilities, such as entropy calculation (based
on password complexity). Validation may also be implemented with regex
 ([code sample](#password-validation-regex)). *Mitigate brute-force attacks.*
- [ ] Lock the account after multiple failed login attempts. Use Devise's 
[lockable module](https://github.com/plataformatec/devise/wiki/How-To:-Add-:lockable-to-Users).
*Mitigates brute-force attacks.*
- [ ] Require users to confirm their e-mail addresses on sign-up and when the 
e-mail address is changed. Use Devise's 
[confirmable module](https://github.com/plataformatec/devise/wiki/How-To:-Add-:confirmable-to-Users)
and set `config.reconfirmable = true` in `config/initializers/devise.rb`. 
*Mitigates the creation of bogus accounts with non-existing or third-party
e-mails.*
- [ ] Require users to input their old password on password change. *Mitigates
unauthorized password changes on session hijacking, CSRF or when a user forgets 
to log out and leaves the PC or mobile device unattended.*
- [ ] Expire the session at log out and expire old sessions at every successful
login. Devise does that by default. Also use Devise's [timeoutable
module](http://www.rubydoc.info/github/plataformatec/devise/Devise/Models/Timeoutable)
to expire sessions after a period of inactivity (e.g., 30 minutes). *Mitigates
CSRF, session hijacking and session fixation attacks by reducing their
time-frame.*
- [ ] Notify user via email on password change. Set
`config.send_password_change_notification = true` in
`config/initializers/devise.rb`.  *Does not prevent an attacker from changing
the victim's password, but warns the victim so he can contact the system
administrator to revoke the attacker's access.*
- [ ] Use generic error messages such as "Invalid email or password" instead 
of specifying which part (e-mail or password) is invalid. Devise does that by
 default. *Mitigates user enumeration and brute-force attacks.*
- [ ] Ensure all non-public controllers/actions require authentication. Add
 `before_acion :authenticate_user!` to `ApplicationController` and 
 `skip_before_action :authenticate_user!` to publicly accessible 
 controllers/actions. *Avoid unauthorized access due to developer 
 forgetfulness.*
- [ ] Consider using the
[devise_security_extension](https://github.com/phatworx/devise_security_extension)
gem, which provides additional security for Devise.
- [ ] Consider using two-factor authentication (2FA) as provided by
[Authy](https://www.authy.com/). See the
[devise-two-factor](https://github.com/tinfoil/devise-two-factor) and
[authy-devise](https://github.com/authy/authy-devise) gems. *Provides a highly
effective extra layer of authentication security.*
- [ ] Consider requiring authentication in `config/routes.rb` by putting 
non-public
resources within a `authenticate :user do` block (see the [Devise
Wiki](https://github.com/plataformatec/devise/wiki/How-To:-Define-resource-actions-that-require-authentication-using-routes.rb)).
Requiring authentication in both controllers and routes may not be DRY, but 
such redundancy provides additional security (see [Defense in
depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing))).
- [ ] Consider restricting administrator access by IP. If the client's IP is 
dynamic, restrict by IP block/ASN or by country via IP geolocation (country).

#### Sessions & Cookies
Broken Authentication and Session Management are #2 at the [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10).
- [ ] Don't store data such as money/point balances or user privileges in a
cookie or a CookieStore Session. Store it in the database instead. *Mitigates 
replay attacks.*
- [ ] Consider always using encrypted cookies. This is the default behavior in  
Rails 4 when `secret_key_base` is set. *Strengthens cookie encryption and 
mitigates multiple attacks involving cookie tampering.*
- [ ] Unless your JavaScript frontend needs to read cookies generated by the
Rails server, set all cookies as `httponly`. Search the project for cookie
accessors and add `httponly: true`. Example: `cookies[:login] = {value: 'user',
httponly: true}`. *Restricts cookie access to the Rails server. Mitigates
attackers from using the victim's browser JavaScript to steal cookies after a
 successful XSS attack.*

Resources:
- [Ruby on Rails Security Guide - Sessions](http://guides.rubyonrails.org/security.html#sessions)

#### Cross-Site Scripting (XSS) 
XSS is #3 at the [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-Top_10).
###### Handling User Input
- [ ] Always validate user input that may eventually be displayed to other
users. Attempting to blacklist characters, strings or sanitize input tends to be
ineffective ([see examples of how to bypass such
blacklists](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)). A
whitelisting approach is usually safer. *Mitigates multiple XSS attacks.*
- [ ] Consider using the
[loofah-activerecord](https://github.com/flavorjones/loofah-activerecord) gem
 to scrub your model attribute values. *Mitigates multiple XSS attacks*.
- [ ] If you must create links from user inputted URLs, be sure to validate
them. If using regex, ensure that the string **begins** with the expected
protocol(s), as in `\Ahttps?`. *Mitigates XSS attacks such as entering 
`javascript:dangerous_stuff()//http://www.some-legit-url.com` as a website URL 
that is displayed as a link to other users (e.g., in a user profile page).*
- [ ] When using regex for input validation, use `\A` and `\z` to match string 
beginning and end. Do **not** use `^` and `$` as anchors. *Mitigates XSS 
attacks that involve slipping JS code after line breaks, such as 
`me@example.com\n<script>dangerous_stuff();</script>`.* 
- [ ] Do not trust validations implemented at the client (frontend) as most 
implementations can be bypassed. Always (re)validate at the server.
###### Output Escaping & Sanitization
- [ ] Escape all HTML output. Rails does that by default, but calling
`html_safe` or `raw` at the view suppresses escaping. Look for calls to these
methods in the entire project, check if you are generating HTML from
user-inputted strings and if those strings are effectively validated. Note that
there are [dozens of ways to evade
validation](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet). If
possible, avoid calling `html_safe` and `raw` altogether. For custom scrubbing,
see
[ActionView::Helpers::SanitizeHelper](http://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html)
Mitigates XSS attacks.*
- [ ] Avoid sending user inputted strings in e-mails to other users. Attackers
may enter a malicious URL in a free text field that is not intended to contain
URLs and does not provide URL validation. Most e-mail clients display URLs as
links.  *Mitigates XSS, phishing, malware infection and other attacks.*

Resources:
- [Ruby on Rails Security Guide - XSS](http://guides.rubyonrails.org/security.html#cross-site-scripting-xss)
- [OWASP XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
- [OWASP Ruby on Rails Cheatsheet - Cross-site Scripting (XSS)](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Cross-site_Scripting_.28XSS.29)
- [Plataformatec Blog - The new HTML sanitizer in Rails 4.2](http://blog.plataformatec.com.br/2014/07/the-new-html-sanitizer-in-rails-4-2)

#### HTTP & TLS
- [ ] Force HTTPS over TLS (formerly known as SSL). Set 
`config.force_ssl = true` in `config/environments/production.rb`. May also be
 done in a TLS termination point such as a load balancer, Nginx or Passenger 
 Standalone. *Mitigates man-in-the-middle and other attacks.* 
- [ ] Use the [SSL Server Test tool from Qualys SSL
Lab](https://www.ssllabs.com/ssltest/) to check the grade of your TLS
certificate. Be sure to use the strongest (yet widely compatible) protocols
and cipher suites, preferably with Ephemeral Diffie-Hellman support.
*Mitigates multiple SSL/TLS-related attacks such as BEAST and POODLE.*
- [ ] Consider rate-limiting incoming HTTP requests, as implemented by the
[rack-attack](https://github.com/kickstarter/rack-attack) and
[rack-throttle](https://github.com/dryruby/rack-throttle) gems. *Mitigates web
scraping, HTTP floods, and other attacks.*
###### Security-related headers
- [ ] Consider using the [Secure Headers
gem](https://github.com/twitter/secureheaders). *Mitigates several attacks.*
- [ ] Consider obfuscating the web server banner string. In other words, hide
 your web server name and version. *Mitigates HTTP fingerprinting, making it 
 harder for attackers to determine which exploits may work on your web server.* 

#### Authorization (Pundit)
- [ ] Implement authorization at the server. Hiding links/controls in the UI is
not enough to protect resources against unauthorized access. *Mitigates forced
browsing attacks.*
- [ ] Ensure all controllers/actions which require authorization call the 
`authorize` or `policy_scope` method ([sample code](#pundit-ensure-all-actions-are-authorized)).
*Mitigates forced browsing attacks due to developers forgetting to require 
authorization in some controller actions.*
- [ ] When using DB records associated to users to populate select
boxes, radio buttons or checkboxes, instead of querying by association
(`user.posts`), consider using `policy_scope`. See [additional details and sample
code](#pundit-ensure-all-actions-are-authorized). *Improves 
readability and maintainability of authorization policies.*

Resources:
- [Pundit: Ensuring policies and scopes are used](https://github.com/elabs/pundit#ensuring-policies-and-scopes-are-used)
- [Pundit: Scopes](https://github.com/elabs/pundit#scopes)

#### Files
###### File Uploads
- [ ] Avoid using user controlled filenames. If possible, assign "random" 
names to uploaded files when storing them in the OS. If not possible, 
whitelist acceptable characters. It is safer to deny uploads with invalid 
characters in the filenames than to attempt to sanitize them.
*Mitigates Directory Traversal Attacks such as attempting to overwrite 
system files by uploading files with names like `../../passwd`.*
- [ ] Avoid using libraries such as ImageMagick to process images and videos 
on your server. If possible, use an image/video processing service such as
[Transloadit](https://transloadit.com/),
[Cloudinary](http://cloudinary.com/features#manipulation), or
[imgix](https://www.imgix.com/solutions). *Mitigates multiple image/video 
processing related vulnerabilities such as [these](https://imagetragick.com).*
- [ ] Process uploaded files asynchronously. If not possible, implement
per-client rate limiting. *Mitigates DoS Attacks that involve overloading the
server CPU by flooding it with uploads that require processing.*  
- [ ] Do not trust validations implemented at the client (frontend) as most 
implementations can be bypassed. Always (re)validate at the server.
- [ ] Validate files before processing. *Mitigates DoS Attacks such
 as image bombs.*
- [ ] Whitelist acceptable file extensions and acceptable Media Types (formerly 
known as MIME types). Validating file extensions without checking their media
 types is not enough as attackers may disguise malicious files by changing 
 their extensions. *Mitigates the upload of dangerous file formats such as shell
  or Ruby scripts.*
- [ ] Limit file size. *Mitigates against DoS attacks involving the 
upload of very large files.*
- [ ] Consider uploading directly from the client (browser) to S3 or a similar
cloud storage service. *Mitigates multiple security issues by keeping uploaded
files on a separate server than your Rails application.*
- [ ] If allowing uploads of malware-prone files (e.g., exe, msi, zip, rar,
pdf), scan them for viruses/malware. If possible, use a third party service to
scan them outside your server. *Mitigates server infection (mostly in Windows
servers) and serving infected files to other users.*
- [ ] If allowing upload of archives such as zip, rar, and gz, validate
the target path, estimated unzip size and media types of compressed files
**before** unzipping. *Mitigates DoS attacks such as zip bombs, zipping 
malicious files in an attempt to bypass validations, and overwriting of system 
files such as `/etc/passwd`.*  
###### File Downloads
- [ ] Do not allow downloading of user-submitted filenames and paths. If not
possible, use a whitelist of permitted filenames and paths. *Mitigates the
exploitation of directory traversal vulnerabilities to download sensitive
files.*

Resources:
- [Ruby on Rails Security Guide - File Uploads and Downloads](http://guides.rubyonrails.org/security.html#file-uploads)

#### Cross-Site Request Forgery (CSRF)
- [ ] Enforce CSRF protection by setting `protect_from_forgery with: 
:exception` in all controllers used by web views or in 
`ApplicationController`.
- [ ] Use HTTP verbs in a RESTful way. Do not use GET requests to alter the
state of resources. *Mitigates CSRF attacks.*
- [ ] Up to Rails 4, there was a single CSRF token for all forms, actions, and
methods. Rails 5 implements per-form CSRF tokens, which are only valid for a
single form and action/method. Enable it by setting
`config.action_controller.per_form_csrf_tokens = true`.

Resources:
- [Ruby on Rails Security Guide - CSRF](http://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf)
- [Big Binary Blog - Each form gets its own CSRF token in Rails 5](http://blog.bigbinary.com/2016/01/11/per-form-csrf-token-in-rails-5.html)


#### Sensitive Data Exposure
- [ ] If possible, avoid storing sensitive data such as credit cards, tax IDs
and third-party authentication credentials in your application. If not 
possible, ensure that all sensitive data is encrypted at rest (in the DB) and
 in transit (use HTTPS over TLS). *Mitigate theft/leakage of sensitive data.*
- [ ] Do not log sensitive data such as passwords and credit card numbers. You
may include parameters that hold sensitive data in `config.filter_parameters` at
`initializers/filter_parameter_logging.rb`. For added security, consider
converting `filter_parameters` into a whitelist. See [sample
code](#convert-filter_parameters-into-a-whitelist). *Prevents plain-text storage
of sensitive data in log files.*
- [ ] HTML comments are viewable to clients and should not contain details that
can be useful to attackers. Consider using server-side comments such as `<%#
This comment syntax with ERB %>` instead of HTML comments. *Avoids exposure of
implementation details.*
- [ ] Avoid exposing numerical/sequential record IDs in URLs, form HTML source
and APIs. Consider using slugs (A.K.A. friendly IDs, vanity URLs) to identify
records instead of numerical IDs, as implemented by the [friendly_id
gem](https://github.com/norman/friendly_id). Additional benefits include SEO and
better-looking URLs. *Mitigates forced browsing attacks and exposure of metrics
about your business, such as the number of registered users, number of 
products on stock, or number of receipts/purchases.*
- [ ] Do not set `config.consider_all_requests_local = true` in the production
environment. If you need to set `config.consider_all_requests_local = true` to
use the [better_errors](https://github.com/charliesome/better_errors) gem, do it
on `config/environments/development.rb`. *Prevents leakage of exceptions and
other information that should only be accessible to developers.*
- [ ] Don't install development/test-related gems such as 
[better_errors](https://github.com/charliesome/better_errors) and 
[web-console](https://github.com/rails/web-console) in the production 
environment. Place them within a `group :development, :test do` block 
in the `Gemfile`. *Prevents leakage of exceptions and even **REPL access** 
if using better_errors + web-console.*
###### Credentials & Secrets
- [ ] Do not commit sensitive data such as `secret_key_base`, DB, and API
credentials to git repositories. Avoid storing credentials in the source code,
use environment variables instead. If not possible, ensure all sensitive files
such as `/config/database.yml`, `config/secrets.yml` (and possibly
`/db/seeds.rb` if it is used to create seed users for production) are included in
`.gitignore`. *Mitigates credential leaks/theft.*
- [ ] Use different secrets in the development and production environments. 
*Mitigates credential leaks/theft.*
- [ ] Use a `secret_key_base` with over 30 random characters. The `rake secret`
 command generates such strong keys. *Strengthens cookie encryption, 
 mitigating multiple cookie/session related attacks.* 

#### Routing, Template Selection, and Redirection
- [ ] Don't perform URL redirection based on user inputted strings. In other 
words, don't pass user input to `redirect_to`. If you have no choice, create 
a whitelist of acceptable redirect URLs or limit to only redirecting to
paths within your domain [(example code)](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Redirects_and_Forwards).
*Mitigates redirection to phishing and malware sites. Prevent attackers from 
providing URLs such as 
`http://www.my-legit-rails-app.com/redirect?to=www.dangeroussite.com` to 
victims.*
- [ ] Do not use a user inputted string to determine the name of the template or
view to be rendered. *Prevents attackers from rendering arbitrary views such as
 admin-only pages.*
- [ ] Avoid "catch-all" routes such as `
match ':controller(/:action(/:id(.:format)))'` and make non-action controller 
methods private. *Mitigates unintended access to controller methods.*
 
 Resources:
 - [OWASP Ruby on Rails Cheatsheet - Redirects and Forwards (URL validation)](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Redirects_and_Forwards)

#### Third-party Software
- [ ] Apply the latest security patches in the OS frequently. Pay special 
attention to internet-facing services such as application servers (Passenger, 
Puma, Unicorn), web servers (Nginx, Apache, Passenger Standalone) and SSH 
servers. 
- [ ] Update Ruby frequently.
- [ ] Watch out for security vulnerabilities in your gems. Run 
[bundler-audit](https://github.com/rubysec/bundler-audit) frequently or use a
 service like [Appcanary](https://appcanary.com/).

#### Security Tools
- [ ] Run [Brakeman](http://brakemanscanner.org/) before each deploy. 
If using an automated code review tool like 
[Code Climate](https://codeclimate.com/), enable the [Brakeman 
engine](https://docs.codeclimate.com/v1.0/docs/brakeman). 
- [ ] Consider using a continuous security service such as
 [Detectify](https://detectify.com/).
- [ ] Consider using a Web Application Firewall (WAF) such as 
[NAXSI](https://github.com/nbs-system/naxsi) for Nginx, 
[ModSecurity](https://github.com/SpiderLabs/ModSecurity) for Apache and Nginx. 
*Mitigates XSS, SQL Injection, DoS, and many other attacks.*

#### Others
- [ ] Use strong parameters in the controllers. This is the default behavior 
as of Rails 4. *Mitigates mass assignment attacks such as overwriting the 
`role` attribute of the `User` model for privilege escalation purposes.*
- [ ] Implement Captcha or Negative Captcha on publicly exposed forms.
[reCAPTCHA](https://developers.google.com/recaptcha/) is a great option, and
there is [a gem](https://github.com/ambethia/recaptcha) that facilitates Rails
integration. Other options are the
[rucaptcha](https://github.com/huacnlee/rucaptcha) and
[negative-captcha](https://github.com/subwindow/negative-captcha) gems. 
*Mitigates automated SPAM (spambots).*


## Details and Code Samples
#### Password validation regex
We may implement password strength validation in Devise by adding the 
following code to the `User` model.
```
validate :password_strength

private

def password_strength
  minimum_length = 8
  # Regex matches at least one lower case letter, one uppercase, and one digit
  complexity_regex = /\A(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/
  # When a user is updated but not its password, the password param is nil
    if password.present? && password.length < minimum_length || !password.match(complexity_regex)
    errors.add :password, 'must be 8 or more characters long, including 
                             at least one lowercase letter, one uppercase
                             letter, and one digit.'
  end
end
```

#### Pundit: ensure all actions are authorized

Add the following to `app/controllers/application_controller.rb`
```
after_action :verify_authorized, except: :index, unless: :devise_controller?
after_action :verify_policy_scoped, only: :index, unless: :devise_controller?
```

Add the following to controllers that do not require authorization. You may 
create a concern for DRY purposes.
```
after_action_skip :verify_authorized
after_action_skip :verify_policy_scoped
```

#### Pundit: only display appropriate records in select boxes
Think of a blog-like news site where users with `editor` role have access to
specific news categories, and `admin` users have access to all categories. The
`User` and the `Category` models have an HMT relationship. When creating a blog
post, there is a select box for choosing a category. We want editors only to see
their associated categories in the select box, but admins must see all
categories. We could populate that select box with `user.categories`. However,
we would have to associate all admin users with all categories (and update these
associations every time a new category is created). A better approach is to use
[Pundit Scopes](https://github.com/elabs/pundit#scopes) to determine which
categories are visible to each user role and use the `policy_scope` method when
populating the select box.

```
# app/views/posts/_form.html.erb
f.collection_select :category_id, policy_scope(Category), :id, :name
```

#### Convert filter_parameters into a whitelist
Developers may forget to add one or more parameters that contain sensitive data
to `filter_parameters`. Whitelists are usually safer than blacklists as they do
not generate security vulnerabilities in case of developer forgetfulness. 
The following code converts `filter_parameters` into a whitelist.

```
# config/initializers/filter_parameter_logging.rb
if Rails.env.production?
  # Parameters whose values are allowed to appear in the production logs:
  WHITELISTED_KEYS = %w(foo bar baz)
  
  # (^|_)ids? matches the following parameter names: id, *_id, *_ids
  WHITELISTED_KEYS_MATCHER = /((^|_)ids?|#{WHITELISTED_KEYS.join('|')})/.freeze
  SANITIZED_VALUE = '[FILTERED]'.freeze
  
  Rails.application.config.filter_parameters << lambda do |key, value|
    unless key.match(WHITELISTED_KEYS_MATCHER)
      value.replace(SANITIZED_VALUE)
    end
  end
else
  # Keep the default blacklist approach in the development environment
  Rails.application.config.filter_parameters += [:password]
end
```


## Authors

- **Bruno Facca** - [LinkedIn](https://www.linkedin.com/in/brunofacca/) - 
Email: bruno at facca dot info

## Contributing

Contributions are welcome. If you would like to correct an error or add new 
items to the checklist, feel free to create an issue and/or a PR. If you are 
interested in contributing regularly, drop me a line at the above e-mail to 
become a collaborator.

## References and Further Reading
- [Ruby on Rails Security Guide](http://guides.rubyonrails.org/security.html)
- [The Rails 4 Way by Obie Fernandez](https://www.amazon.com/Ruby-Rails-Tutorial-Addison-Wesley-Professional/dp/0134598628/ref=pd_lpo_sbs_14_t_0?_encoding=UTF8&psc=1&refRID=G6PXCRKW09VRHMY07MV2), Chapter 15
- [OWASP Top Ten](https://www.owasp.org/index.php/Top_10_2013-Top_10)
- [SitePoint: Common Rails Security Pitfalls and Their Solutions](https://www.sitepoint.com/common-rails-security-pitfalls-and-their-solutions/)
- [Rails Security Audit by Hardhat](https://github.com/hardhatdigital/rails-security-audit)
- [Rails Security Checklist by Eliot Sykes](https://github.com/eliotsykes/rails-security-checklist)

## License

Released under the [MIT License](https://opensource.org/licenses/MIT).
