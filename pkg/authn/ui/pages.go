// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ui

// PageTemplates stores UI templates.
var PageTemplates = map[string]string{
	"basic/login": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/login.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  {{ $authenticatorCount := len .Data.login_options.authenticators }}
  {{ $qrCodeLink := pathjoin .ActionEndpoint "/qrcode/login.png" }}


  <body class="h-full">
    <div class="app-page">
      <div class="app-content">
        <div class="app-container">
          <div class="logo-box">
            {{ if .LogoURL }}
              <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
            {{ end }}
            <h2 class="logo-txt">{{ .PageTitle }}</h2>
          </div>

          {{ if eq .Data.login_options.form_required "yes" }}
            <div id="loginform" {{ if ne $authenticatorCount 1 }}class="hidden"{{ end }}>
              <div>
                <form class="space-y-6" action="{{ pathjoin .ActionEndpoint "/login" }}" method="POST">
                  <div>
                    <label for="username" class="block text-center pb-2 text-lg font-sans font-medium text-primary-700">Please provide username or email address</label>
                    <div class="app-inp-box">
                      <div class="app-inp-prf-img"><i class="las la-user"></i></div>
                      <input class="app-inp-txt" id="username" name="username" type="text" autocorrect="off" autocapitalize="off" spellcheck="false" autofocus required />
                    </div>
                  </div>

                  {{ if eq .Data.login_options.realm_dropdown_required "yes" }}
                    <div class="hidden">
                      <select id="realm" name="realm" class="app-inp-sel">
                        {{ range .Data.login_options.realms }}
                          {{ if eq .default "yes" }}
                            <option value="{{ .realm }}" selected>{{ .label }}</option>
                          {{ else }}
                            <option value="{{ .realm }}">{{ .label }}</option>
                          {{ end }}
                        {{ end }}
                      </select>
                    </div>
                  {{ else }}
                    {{ range .Data.login_options.realms }}
                      <div class="hidden">
                        <input type="hidden" id="realm" name="realm" value="{{ .realm }}" />
                      </div>
                    {{ end }}
                  {{ end }}


                  <div class="flex gap-4">
                    {{ if ne $authenticatorCount 1 }}
                      <div class="flex-none">
                        <button type="button" onclick="hideLoginForm();return false;" class="app-btn-sec">
                          <div><i class="las la-caret-left"></i></div>
                          <div class="pl-1 pr-2"><span>Back</span></div>
                        </button>
                      </div>
                    {{ end }}
                    <div class="grow">
                      <button type="submit" class="app-btn-pri">
                        <div><i class="las la-check-circle"></i></div>
                        <div class="pl-2"><span>Proceed</span></div>
                      </button>
                    </div>
                  </div>
                </form>
              </div>

              <div id="user_actions" class="flex flex-wrap pt-6 justify-center gap-4{{ if or (ne $authenticatorCount 1) (eq .Data.login_options.hide_links "yes") }} hidden{{ end -}}">
                <div id="user_register_link"{{ if eq .Data.login_options.hide_register_link "yes" }} class="hidden"{{ end -}}>
                  <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/register" .Data.login_options.default_realm }}">
                    <i class="las la-book"></i>
                    <span class="text-lg">Register</span>
                  </a>
                </div>

                <div id="forgot_username_link"{{ if eq .Data.login_options.hide_forgot_username_link "yes" }} class="hidden"{{ end -}}>
                  <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/forgot" .Data.login_options.default_realm }}">
                    <i class="las la-unlock"></i>
                    <span class="text-lg">Forgot Username?</span>
                  </a>
                </div>

                <div id="contact_support_link"{{ if eq .Data.login_options.hide_contact_support_link "yes" }} class="hidden"{{ end -}}>
                  <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/help" .Data.login_options.default_realm }}">
                    <i class="las la-info-circle"></i>
                    <span class="text-lg">Contact Support</span>
                  </a>
                </div>
              </div>
            </div>
          {{ end }}

          {{ if eq .Data.login_options.authenticators_required "yes" }}
            <div id="authenticators" class="flex flex-col gap-2">
              {{ range .Data.login_options.authenticators }}
                <div>
                  {{ if .endpoint }}
                    <a href="{{ .endpoint }}">
                      <div class="app-login-btn-box">
                        <div class="p-4 bg-[{{ .background_color }}] text-[{{ .color }}] shadow-sm rounded-l-md text-2xl">
                          <i class="{{ .class_name }}"></i>
                        </div>
                        <div class="app-login-btn-txt">
                          <span class="uppercase leading-loose">{{ .text }}</span>
                        </div>
                      </div>
                    </a>
                  {{ else }}
                    <a href="#" onclick="showLoginForm('{{ .realm }}', '{{ .registration_enabled }}', '{{ .username_recovery_enabled }}', '{{ .contact_support_enabled }}', '{{ .ActionEndpoint }}');return false;">
                      <div class="app-login-btn-box">
                        <div class="p-4 bg-[{{ .background_color }}] text-[{{ .color }}] shadow-sm rounded-l-md text-2xl">
                          <i class="{{ .class_name }}"></i>
                        </div>
                        <div class="app-login-btn-txt">
                          <span class="uppercase leading-loose">{{ .text }}</span>
                        </div>
                      </div>
                    </a>
                  {{ end }}
                </div>
              {{ end }}
            </div>
          {{ end }}
        </div>
        <div id="bookmarks" class="px-4 hidden sm:block">
          <div onclick="showQRCode('{{ $qrCodeLink }}');return false;" class="bg-[#24292f] text-[#f6f8fa] py-1 px-1 shadow-xl rounded-b-lg pb-2 text-center" style="max-width: 3em;">
            <i class="las la-qrcode text-3xl"></i>
          </div>
        </div>
        <div id="qr" class="px-4 flex justify-center hidden">
          <div id="qrcode" onclick="hideQRCode();return false;" class="bg-white border border-t-2 py-1 px-1 shadow-xl rounded-b-lg pb-2 max-w-xs inline-flex"></div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/login.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
	"basic/portal": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/portal.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content">
        <div class="app-container">
          <div class="logo-col-box justify-center">
            {{ if .LogoURL }}
              <div>
                <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
              </div>
            {{ end }}
            <div>
              <h2 class="logo-col-txt">{{ .PageTitle }}</h2>
            </div>
          </div>
          <div>
            <p class="app-inp-lbl">Access the following services.</p>
          </div>
          <div class="mt-3 grid">
            {{ range .PrivateLinks }}
              <div class="pb-2">
                <a href="{{ .Link }}" {{ if .TargetEnabled }}target="{{ .Target }}"{{ end }}>
                  <div class="app-portal-btn-box">
                    <div class="app-portal-btn-img">{{ if .IconEnabled -}}<i class="{{ .IconName }}"></i>{{- end }}</div>
                    <div class="app-portal-btn-txt"><span>{{ .Title }}</span></div>
                  </div>
                </a>
              </div>
            {{ end }}
            <div class="pb-2">
              <a href="{{ pathjoin .ActionEndpoint "/logout" }}">
                <div class="app-portal-btn-box">
                  <div class="app-portal-btn-img"><i class="las la-sign-out-alt"></i></div>
                  <div class="app-portal-btn-txt"><span>Sign Out</span></div>
                </div>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/portal.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
	"basic/whoami": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/whoami.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content md:max-w-2xl lg:max-w-4xl">
        <div class="app-container">
          <div class="logo-col-box justify-center">
            {{ if .LogoURL }}
              <div>
                <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
              </div>
            {{ end }}
            <div>
              <h2 class="logo-col-txt">{{ .PageTitle }}</h2>
            </div>
          </div>

          <div class="mt-3">
            <pre><code class="language-json hljs">{{ .Data.token }}</code></pre>
          </div>

          <div class="flex flex-wrap pt-6 justify-center gap-4">
            <div id="forgot_username_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/portal" }}">
                <i class="las la-layer-group"></i>
                <span class="text-lg">Portal</span>
              </a>
            </div>
            <div id="contact_support_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/logout" }}">
                <i class="las la-times-circle"></i>
                <span class="text-lg">Sign Out</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/whoami.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    <script>
      hljs.initHighlightingOnLoad();
    </script>
  </body>
</html>`,
	"basic/register": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/montserrat.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/register.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content {{ if eq .Data.view "register" }}md:max-w-2xl lg:max-w-4xl{{ end }}">
        <div class="app-container">
          <div class="logo-col-box justify-center">
            {{ if .LogoURL }}
              <div>
                <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
              </div>
            {{ end }}
            <div>
              <h2 class="logo-col-txt">{{ .PageTitle }}</h2>
            </div>
          </div>

          {{ if .Message }}
          <div id="alerts" class="rounded-md bg-red-50 p-4">
            <div class="flex items-center">
              <div class="flex-shrink-0"><i class="las la-exclamation-triangle text-2xl text-red-600"></i></div>
              <div class="ml-3"><p class="text-sm font-medium text-red-800">{{ .Message }}</p></div>
              <div class="ml-auto pl-3">
                <div class="-mx-1.5 -my-1.5">
                  <button type="button" onclick="hideAlert(); return false;" class="app-alert-banner">
                    <span class="sr-only">Dismiss</span>
                    <i class="las la-times text-2xl text-red-600"></i>
                  </button>
                </div>
              </div>
            </div>
          </div>
          {{ end }}

          <div class="mt-3">
              {{ if eq .Data.view "register" }}
              <form method="POST" action="{{ pathjoin .ActionEndpoint "/register" }}" class="grid grid-cols-1 gap-y-6 sm:grid-cols-2 sm:gap-x-8">
              {{ end }}

              {{ if eq .Data.view "ack" }}
              <form method="POST" action="{{ pathjoin .ActionEndpoint "/register/ack" .Data.registration_id }}">
              {{ end }}

              {{ if eq .Data.view "register" }}
                <div>
                  <label for="registrant" class="app-gen-inp-lbl">Username</label>
                  <div class="mt-1">
                    <input id="registrant" name="registrant" type="text" 
                      class="app-gen-inp-txt validate"
                      pattern="{{ .Data.username_validate_pattern }}"
                      title="{{ .Data.username_validate_title }}"
                      autocorrect="off" autocapitalize="off" autocomplete="username" spellcheck="false"
                      required
                      />
                  </div>
                </div>
                <div>
                  <label for="registrant_password" class="app-gen-inp-lbl">Password</label>
                  <div class="mt-1">
                    <input type="password" name="registrant_password" id="registrant_password"
                      class="app-gen-inp-txt validate"
                      pattern="{{ .Data.password_validate_pattern }}"
                      title="{{ .Data.password_validate_title }}"
                      autocorrect="off" autocapitalize="off" autocomplete="current-password" spellcheck="false"
                      required
                    />
                  </div>
                </div>
                <div>
                  <label for="registrant_email" class="app-gen-inp-lbl">Email</label>
                  <div class="mt-1">
                    <input id="registrant_email" name="registrant_email" type="email" autocomplete="email"
                      class="app-gen-inp-txt validate" 
                      autocorrect="off" autocapitalize="off" autocomplete="email" spellcheck="false"
                      required
                    />
                  </div>
                </div>
                <div>
                  <label for="first_name" class="app-gen-inp-lbl">First name</label>
                  <div class="mt-1">
                    <input type="text" name="first_name" id="first_name"
                      class="app-gen-inp-txt"
                      autocorrect="off" autocapitalize="off" autocomplete="off" spellcheck="false"
                    />
                  </div>
                </div>
                <div>
                  <label for="last_name" class="app-gen-inp-lbl">Last name</label>
                  <div class="mt-1">
                    <input type="text" name="last_name" id="last_name"
                      class="app-gen-inp-txt"
                      autocorrect="off" autocapitalize="off" autocomplete="off" spellcheck="false"
                    />
                  </div>
                </div>

                {{ if .Data.require_registration_code }}
                <div>
                  <label for="registrant_code" class="app-gen-inp-lbl">Registration Code</label>
                  <div class="mt-1">
                    <input type="text" id="registrant_code" name="registrant_code"
                      class="app-gen-inp-txt validate"
                      autocorrect="off" autocapitalize="off" autocomplete="off" spellcheck="false"
                    />
                  </div>
                </div>
                {{ end }}

                {{ if .Data.require_accept_terms }}
                <div class="sm:col-span-2">
                  <div class="flex items-start">
                    <div class="flex-shrink-0">
                      <input id="accept_terms" name="accept_terms" type="checkbox" 
                        aria-describedby="comments-description"
                        class="focus:ring-primary-500 h-4 w-4 text-primary-600 border-gray-300 rounded"
                        required
                      />
                    </div>
                    <div class="ml-3">
                      <p class="text-base text-gray-500">
                        By selecting this, you agree to the
                        <a href="{{ .Data.terms_conditions_link }}" target="_blank" class="font-medium text-gray-700 underline">Terms and Conditions</a>
                        and
                        <a href="{{ .Data.privacy_policy_link }}" target="_blank" class="font-medium text-gray-700 underline">Privacy Policy</a>.
                      </p>
                    </div>
                  </div>
                </div>
                {{ end }}
              {{ end }}

              {{ if eq .Data.view "registered" }}
              <div class="app-txt-section">
                <p>Thank you for registering and we hope you enjoy the experience!</p>
                <p>Here are a few things to keep in mind:</p>
                <ol class="list-decimal pl-8">
                  <li>You should receive your confirmation email within the next 15 minutes.</li>
                  <li>If you still don't see it, please email support so we can resend it to you.</li>
                </ol>
              </div>
              {{ end }}

              {{ if eq .Data.view "ack" }}
              <div class="pb-4">
                <label for="registration_code" class="app-inp-lbl">Passcode</label>
                <div class="app-inp-box">
                  <input id="registration_code" name="registration_code" type="text"
                         class="font-['Montserrat'] app-inp-code-txt validate"
                         pattern="[A-Za-z0-9]{6,8}" maxlength="8"
                         title="The registration code should be 6-8 characters long."
                         autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                         required />
                </div>
              </div>
              {{ end }}

              {{ if eq .Data.view "ackfail" }}
              <div class="app-txt-section">
                <p>Unfortunately, things did not go as expected. {{ .Data.message }}.</p>
              </div>
              {{ end }}

              {{ if eq .Data.view "acked" }}

              <div class="app-txt-section">
                <p>Thank you for confirming your registration and validating your email address!</p>
                <p>At this point, once an administrator approves or disapproves your registration,
                  you will get an email about that decision. If approved, you will be able to login with your
                  credentials right away.
                </p>
              </div>
              {{ end }}

              <div class="sm:col-span-2">
                <div class="flex gap-4 justify-end">
                  {{ if eq .Data.view "register" }}
                  <a href="{{ .ActionEndpoint }}">
                    <button type="button" name="portal" class="app-btn-sec">
                      <div><i class="las la-home"></i></div>
                      <div class="pl-1 pr-2"><span>Home</span></div>
                    </button>
                  </a>
                  <button type="reset" name="reset" class="app-btn-sec">
                    <div><i class="las la-redo-alt"></i></i></div>
                    <div class="pl-1 pr-2"><span>Clear</span></div>
                  </button>
                  <button type="submit" name="submit" class="app-btn-pri">
                    <div><i class="las la-check"></i></div>
                    <div class="pl-1 pr-2"><span>Submit</span></div>
                  </button>
                  {{ end }}

                  {{ if and (ne .Data.view "register") (ne .Data.view "ack") }}
                  <a href="{{ .ActionEndpoint }}">
                    <button type="button" name="portal" class="app-btn-sec">
                      <div><i class="las la-home"></i></div>
                      <div class="pl-1 pr-2"><span>Home</span></div>
                    </button>
                  </a>
                  {{ end }}

                  {{ if eq .Data.view "ack" }}
                  <a href="{{ .ActionEndpoint }}">
                    <button type="button" name="portal" class="app-btn-sec">
                      <div><i class="las la-home"></i></div>
                    </button>
                  </a>
                  <button type="reset" name="reset" class="app-btn-sec">
                    <div><i class="las la-redo-alt"></i></i></div>
                    <div class="pl-1 pr-2"><span>Clear</span></div>
                  </button>
                  <button type="submit" name="submit" class="app-btn-pri">
                    <div><i class="las la-check"></i></div>
                    <div class="pl-1 pr-2"><span>Submit</span></div>
                  </button>
                  {{ end }}
                </div>
              </div>

            {{ if or (eq .Data.view "register") (eq .Data.view "ack") }}
            </form>
            {{ end }}
            
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/register.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if .Message }}
    <script>
    function hideAlert() {
      document.getElementById("alerts").remove();
    }
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/generic": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/generic.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content md:max-w-2xl lg:max-w-2xl">
        <div class="bg-white py-8 px-4 shadow-lg sm:rounded-lg sm:px-10">
          <div class="bg-white min-h-full px-4 py-16 sm:px-6 sm:py-24 md:grid md:place-items-center lg:px-8">
            <div class="max-w-max mx-auto">
              <main class="sm:flex">
                {{ if .LogoURL }}
                  <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
                {{ end }}
                <div class="sm:ml-6">
                  <div class="app-gen-banner-box">
                    <h1 class="app-gen-banner-header">{{ .PageTitle }}</h1>
                    <p class="app-gen-banner-message">{{ .Data.message }}</p>
                  </div>
                  {{ if .Data.go_back_url }}
                    <div class="app-gen-btn-box">
                      <a href="{{ .Data.go_back_url }}" class="app-gen-btn-txt"> Go back </a>
                    </div>
                  {{ end }}
                </div>
              </main>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/generic.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
	"basic/settings": `<!doctype html>
<html lang="en">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">

    <!-- Matrialize CSS -->
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/materialize-css/css/materialize.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/montserrat.css" }}" />
    {{ end }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    {{ end }}
    {{ if or (eq .Data.view "apikeys-add") (eq .Data.view "apikeys-add-status") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/highlight.js/css/atom-one-dark.min.css" }}" />
    {{ end }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/styles.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/mfa_app.css" }}" />
    {{ end }}
  </head>
  <body class="app-body">
    <div class="container app-container">
      <div class="row">
        <nav>
          <div class="nav-wrapper">
            {{ if .LogoURL }}
            <img src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
            {{ end }}
            <a href="#" class="brand-logo">{{ .PageTitle }}</a>
            <ul id="nav-mobile" class="right hide-on-med-and-down">
              <li>
                <a href="{{ pathjoin .ActionEndpoint "/portal" }}">
                  <button type="button" class="btn waves-effect waves-light navbtn active">
                    <span class="app-btn-text">Portal</span>
                    <i class="las la-home left app-btn-icon app-navbar-btn-icon"></i>
                 </button>
                </a>
              </li>
              <li>
                <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="navbtn-last">
                  <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last">
                    <span class="app-btn-text">Logout</span>
                    <i class="las la-sign-out-alt left app-btn-icon app-navbar-btn-icon"></i>
                  </button>
                </a>
              </li>
            </ul>
          </div>
        </nav>
      </div>
      <div class="row">
        <div class="col s12 l3">
          <div class="collection">
            <a href="{{ pathjoin .ActionEndpoint "/settings/" }}" class="collection-item{{ if eq .Data.view "general" }} active{{ end }}">General</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}" class="collection-item{{ if eq .Data.view "sshkeys" }} active{{ end }}">SSH Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}" class="collection-item{{ if eq .Data.view "gpgkeys" }} active{{ end }}">GPG Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys" }}" class="collection-item{{ if eq .Data.view "apikeys" }} active{{ end }}">API Keys</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}" class="collection-item{{ if eq .Data.view "mfa" }} active{{ end }}">MFA</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/password" }}" class="collection-item{{ if eq .Data.view "password" }} active{{ end }}">Password</a>
            <a href="{{ pathjoin .ActionEndpoint "/settings/connected" }}" class="collection-item{{ if eq .Data.view "connected" }} active{{ end }}">Connected Accounts</a>
            <a href="{{ pathjoin .ActionEndpoint "/portal" }}" class="hide-on-med-and-up collection-item">Portal</a>
            <a href="{{ pathjoin .ActionEndpoint "/logout" }}" class="hide-on-med-and-up collection-item">Logout</a>
          </div>
        </div>
        <div class="col s12 l9 app-content">
          {{ if eq .Data.view "general" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
            <p>
            <b>ID</b>: {{ .Data.metadata.ID }}<br/>
            {{ if .Data.metadata.Name }}<b>Name</b>: {{ .Data.metadata.Name }}<br/>{{ end }}
            {{ if .Data.metadata.Title }}<b>Title</b>: {{ .Data.metadata.Title }}<br/>{{ end }}
            <b>Username</b>: {{ .Data.metadata.Username }}<br/>
            <b>Email</b>: {{ .Data.metadata.Email }}<br/>
            <b>Created</b>: {{ .Data.metadata.Created }}<br/>
            <b>LastModified</b>: {{ .Data.metadata.LastModified }}<br/>
            <b>Revision</b>: {{ .Data.metadata.Revision }}
            </p>
            {{ else }}
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "sshkeys" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add SSH Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.sshkeys }}
              {{range .Data.sshkeys}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    <b>Type:</b> {{ .Type }}<br/>
                    <b>Fingerprint (SHA256)</b>: {{ .Fingerprint }}<br/>
                    <b>Fingerprint (MD5)</b>: {{ .FingerprintMD5 }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/delete" .ID }}">Delete</a>
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/sshkeys/view" .ID }}">View</a>
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered SSH Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "sshkeys-add" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add SSH Key</h1>
                  <p>Please paste your public SSH key here.</p>
                  <div class="input-field shell-textarea-wrapper">
                    <textarea id="key1" name="key1" class="hljs shell-textarea"></textarea>
                  </div>
                  <div class="input-field">
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" autocorrect="off" autocapitalize="off" autocomplete="off" class="validate">
                  </div>
                  <div class="right">
                    <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                      <i class="las la-plus-circle left app-btn-icon"></i>
                      <span class="app-btn-text">Add SSH Key</span>
                    </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "sshkeys-add-status" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Public SSH Key</h1>
              <p>{{ .Data.status_reason }}</p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <h1>Public SSH Key</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "sshkeys-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Public SSH Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add GPG Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.gpgkeys }}
              {{range .Data.gpgkeys}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    <b>Usage:</b> {{ .Usage }}<br/>
                    <b>Type:</b> {{ .Type }}<br/>
                    <b>Fingerprint</b>: {{ .Fingerprint }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/gpgkeys/delete" .ID }}">Delete</a>
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/gpgkeys/view" .ID }}">View</a>
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered GPG Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-add" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add GPG Key</h1>
                  <p>Please paste your public GPG key here.</p>
                  <div class="input-field shell-textarea-wrapper">
                      <textarea id="key1" name="key1" class="hljs shell-textarea"></textarea>
                  </div>
                  <div class="input-field">
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" autocorrect="off" autocapitalize="off" autocomplete="off" class="validate">
                  </div>
                  <div class="right">
                    <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                      <i class="las la-plus-circle left app-btn-icon"></i>
                      <span class="app-btn-text">Add GPG Key</span>
                    </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-add-status" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Public GPG Key</h1>
              <p>{{ .Data.status_reason }}</p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <h1>Public GPG Key</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "gpgkeys-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Public GPG Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if or (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
          <div class="row">
            <div class="col s12">
              {{ if eq .Data.view "gpgkeys-view" }}
              <h1>GPG Key</h1>
              {{ else }}
              <h1>SSH Key</h1>
              {{ end }}
              <pre><code class="language-json hljs">{{ .Data.key }}</code></pre>
              {{ if .Data.pem_key }}
              <h5>PEM</h5>
              <pre><code class="language-text hljs">{{ .Data.pem_key }}</code></pre>
              {{ end }}
              {{ if .Data.openssh_key }}
              <h5>OpenSSH</h5>
              <pre><code class="language-text hljs">{{ .Data.openssh_key }}</code></pre>
              {{ end }}
              {{ if eq .Data.view "gpgkeys-view" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/gpgkeys" }}">
              {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/sshkeys" }}">
              {{ end }}
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "apikeys" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys/add" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add API Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.apikeys }}
              {{range .Data.apikeys}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/apikeys/delete" .ID }}">Delete</a>
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered API Keys found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "apikeys-add" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/apikeys/add" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add API Key</h1>
                  <p>Please provide a nickname to identify your new API key.</p>
                  <div class="input-field">
                    <input placeholder="Comment" name="comment1" id="comment1" type="text" autocorrect="off" autocapitalize="off" autocomplete="off" class="validate">
                  </div>
                  <div class="right">
                    <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                      <i class="las la-plus-circle left app-btn-icon"></i>
                      <span class="app-btn-text">Add API Key</span>
                    </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "apikeys-add-status" }}
          <div class="row">
            <div class="col s12">
              <h1>API Key</h1>
              {{ if eq .Data.status "SUCCESS" }}
              <p>Keep this key secret!</p>
              <pre><code class="language-text hljs">{{ .Data.api_key }}</code></pre>
              {{ else }}
              <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
              {{ end }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "apikeys-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>API Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/apikeys" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}


          {{ if eq .Data.view "mfa" }}
          <div class="row right">
            <div class="col s12 right">
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active app-btn">
                  <i class="las la-mobile-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Add MFA App</span>
                </button>
              </a>
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}" class="navbtn-last">
                <button type="button" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-key left app-btn-icon"></i>
                  <span class="app-btn-text">Add U2F Key</span>
                </button>
              </a>
            </div>
          </div>
          <div class="row">
            <div class="col s12">
            {{ if .Data.mfa_tokens }}
              {{range .Data.mfa_tokens}}
              <div class="card">
                <div class="card-content">
                  <span class="card-title">{{ .Comment }}</span>
                  <p>
                    <b>ID</b>: {{ .ID }}<br/>
                    {{ if eq .Type "u2f" }}
                    <b>Type</b>: Hardware/U2F Token<br/>
                    {{ else }}
                    <b>Type</b>: Authenticator App<br/>
                    <b>Algorithm</b>: {{ .Algorithm }}<br/>
                    <b>Period</b>: {{ .Period }} seconds<br/>
                    <b>Digits</b>: {{ .Digits }}<br/>
                    {{ end }}
                    <b>Created At</b>: {{ .CreatedAt }}
                  </p>
                </div>
                <div class="card-action">
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/delete/" .ID }}">Delete</a>
                  {{ if eq .Type "totp" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/app/" (printf "%d" .Digits) .ID }}">Test</a>
                  {{ end }}
                  {{ if eq .Type "u2f" }}
                  <a href="{{ pathjoin $.ActionEndpoint "/settings/mfa/test/u2f/generic" .ID }}">Test</a>
                  {{ end }}
                </div>
              </div>
              {{ end }}
            {{ else }}
              <p>No registered MFA devices found</p>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-add-app" }}
            <form id="mfa-add-app-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}" method="POST">
              <div class="row">
                <h1>Add MFA Authenticator Application</h1>
                <div class="col s12 m11 l11">
                  <div id="token-params">
                    <h6 id="token-params-mode" class="hide">Token Parameters</h6>
                    <p><b>Step 1</b>: Amend the label and comment associated with the authenticator.
                      The label is what you would see in your authenticator app.
                      The comment is what you would see in this portal.
                    </p>
                    <div class="input-field">
                      <input id="label" name="label" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                        title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                        maxlength="25"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        value="{{ .Data.mfa_label }}"
                        required />
                      <label for="label">Label</label>
                    </div>
                    <div class="input-field">
                      <input id="comment" name="comment" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                        title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                        maxlength="25"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        value="{{ .Data.mfa_comment }}"
                        required />
                      <label for="comment">Comment</label>
                    </div>
                    <p><b>Step 1a</b> (<i>optional</i>): If necessary, click
                      <a href="#advanced-setup-mode" onclick="toggleAdvancedSetupMode()">here</a> to customize default values.
                    </p>
                    <div id="advanced-setup-all" class="hide">
                      <h6 id="advanced-setup-mode" class="hide">Advanced Setup Mode</h6>
                      <div id="advanced-setup-secret" class="input-field">
                        <input id="secret" name="secret" type="text" class="validate" pattern="[A-Za-z0-9]{10,100}"
                          title="Token secret should contain 10-200 characters and consists of A-Z and 0-9 characters only."
                          autocorrect="off" autocapitalize="off" autocomplete="off"
                          maxlength="100"
                          value="{{ .Data.mfa_secret }}"
                          required />
                        <label for="secret">Token Secret</label>
                      </div>
                      <div id="advanced-setup-period" class="input-field">
                        <select id="period" name="period" class="browser-default">
                          <option value="15" {{ if eq .Data.mfa_period "15" }} selected{{ end }}>15 Seconds Lifetime</option>
                          <option value="30" {{ if eq .Data.mfa_period "30" }} selected{{ end }}>30 Seconds Lifetime</option>
                          <option value="60" {{ if eq .Data.mfa_period "60" }} selected{{ end }}>60 Seconds Lifetime</option>
                          <option value="90" {{ if eq .Data.mfa_period "90" }} selected{{ end }}>90 Seconds Lifetime</option>
                        </select>
                      </div>
                      <div id="advanced-setup-digits" class="input-field">
                        <select id="digits" name="digits" class="browser-default">
                          <option value="4" {{ if eq .Data.mfa_digits "4" }} selected{{ end }}>4 Digit Code</option>
                          <option value="6" {{ if eq .Data.mfa_digits "6" }} selected{{ end }}>6 Digit Code</option>
                          <option value="8" {{ if eq .Data.mfa_digits "8" }} selected{{ end }}>8 Digit Code</option>
                        </select>
                      </div>
                    </div>
                    <p><b>Step 2</b>: Open your MFA authenticator application, e.g. Microsoft/Google Authenticator, Authy, etc.,
                      add new entry and click the "Get QR" link.
                    </p>
                    <div id="mfa-get-qr-code" class="center-align">
                      <a href="#qr-code-mode" onclick="getQRCode()">Get QR Code</a>
                    </div>
                  </div>
                  <div id="mfa-qr-code" class="hide">
                    <h6 id="qr-code-mode" class="hide">QR Code Mode</h6>
                    <div class="center-align">
                      <p>&raquo; Scan the QR code image.</p>
                    </div>
                    <div id="mfa-qr-code-image" class="center-align">
                      <img src="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/" .Data.code_uri_encoded }}.png" alt="QR Code" />
                    </div>
                    <div class="center-align">
                      <p>&raquo; Can't scan? Click or copy the link below.</p>
                    </div>
                    <div id="mfa-no-camera-link" class="center-align">
                      <a href="{{ .Data.code_uri }}">No Camera Link</a>
                    </div>
                    <p><b>Step 3</b>: Enter the authentication code you see in the app and click "Add".</p>
                    <div class="input-field mfa-app-auth-ctrl mfa-app-auth-form">
                      <input class="mfa-app-auth-passcode" id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{4,8}"
                        title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        placeholder="______"
                        required />
                    </div>
                    <input id="email" name="email" type="hidden" value="{{ .Data.mfa_email }}" />
                    <input id="type" name="type" type="hidden" value="{{ .Data.mfa_type }}" />
                    <input id="barcode_uri" name "barcode_uri" type="hidden" value="{{ pathjoin .ActionEndpoint "/settings/mfa/barcode/"}}" />
                    <div class="row right">
                      <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                        <i class="las la-plus-circle left app-btn-icon"></i>
                        <span class="app-btn-text">Add</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-add-app-status" }}
          <div class="row">
            <div class="col s12">
            <h1>MFA Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/app" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-test-app" }}
            <form id="mfa-test-app-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_digits .Data.mfa_token_id }}" method="POST">
              <div class="row">
                <h1>Test MFA Authenticator Application</h1>
                <div class="row">
                  <div class="col s12 m12 l12">
                    <p>Please open your MFA authenticator application to view your authentication code and verify your identity</p>
                    <div class="input-field mfa-app-auth-ctrl mfa-app-auth-form">
                      <input class="mfa-app-auth-passcode" id="passcode" name="passcode" type="text" class="validate" pattern="[0-9]{4,8}"
                        title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                        maxlength="6"
                        autocorrect="off" autocapitalize="off" autocomplete="off"
                        placeholder="______"
                        required />
                    </div>
                    <input id="token_id" name="token_id" type="hidden" value="{{ .Data.mfa_token_id }}" />
                    <input id="digits" name="digits" type="hidden" value="{{ .Data.mfa_digits }}" />
                    <div class="center-align">
                      <button type="reset" name="reset" class="btn waves-effect waves-light navbtn active navbtn-last red lighten-1">
                        <i class="las la-redo-alt left app-btn-icon"></i>
                      </button>
                      <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last">
                        <i class="las la-check-square left app-btn-icon"></i>
                        <span class="app-btn-text">Verify</span>
                      </button>
                  </div>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-test-app-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Test MFA Authenticator Application</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              {{ if ne .Data.mfa_token_id "" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/test/app/" .Data.mfa_digits .Data.mfa_token_id }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
              {{ end }}
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-delete-status" }}
          <div class="row">
            <div class="col s12">
            <h1>MFA Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
              <button type="button" class="btn waves-effect waves-light navbtn active">
                <i class="las la-undo-alt left app-btn-icon"></i>
                <span class="app-btn-text">Go Back</span>
              </button>
            </a>
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-add-u2f" }}
            <form id="mfa-add-u2f-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}" method="POST">
              <div class="row">
                <div class="col s12">
                  <h1>Add U2F Security Key</h1>
                  <p>Please insert your U2F (USB, NFC, or Bluetooth) Security Key, e.g. Yubikey.</p>
                  <p>Then, please click "Register" button below.</p>
                  <div class="input-field">
                    <input id="comment" name="comment" type="text" class="validate" pattern="[A-Za-z0-9 -]{4,25}"
                      title="Authentication code should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                      autocorrect="off" autocapitalize="off" autocomplete="off"
                      required />
                    <label for="comment">Comment</label>
                  </div>
                  <input class="hide" id="webauthn_register" name="webauthn_register" type="text" />
                  <input class="hide" id="webauthn_challenge" name="webauthn_challenge" type="text" value="{{ .Data.webauthn_challenge }}" />
                  <button id="mfa-add-u2f-button" type="button" name="action" onclick="u2f_token_register('mfa-add-u2f-form', 'mfa-add-u2f-button');" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                    <i class="las la-plus-circle left app-btn-icon"></i>
                    <span class="app-btn-text">Register</span>
                  </button>
                </div>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-add-u2f-status" }}
          <div class="row">
            <div class="col s12">
            <h1>U2F Security Key</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/add/u2f" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "mfa-test-u2f" }}
            <form id="mfa-test-u2f-form" action="{{ pathjoin .ActionEndpoint "/settings/mfa/test/u2f/generic" .Data.mfa_token_id }}" method="POST">
              <div class="row">
                <div class="col s12 m12 l12">
                  <h1>Test Token</h1>
                  <p>
                    Insert your hardware token into a USB port.
                    Next, click "Authenticate" button below.
                    When prompted, touch, or otherwise trigger the hardware token.
                  </p>
                  <input id="webauthn_request" name="webauthn_request" type="hidden" />
                  <a id="mfa-test-u2f-button" onclick="u2f_token_authenticate('mfa-test-u2f-form', 'mfa-test-u2f-button');" class="btn waves-effect waves-light navbtn active navbtn-last">
                    <i class="las la-check-square left app-btn-icon"></i>
                    <span class="app-btn-text">Verify</span>
                  </a>
                </div>
                <input id="token_id" name="token_id" type="hidden" value="{{ .Data.mfa_token_id }}" />
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "mfa-test-u2f-status" }}
          <div class="row">
            <div class="col s12">
            <h1>Test Token</h1>
            <p>{{.Data.status }}: {{ .Data.status_reason }}</p>
            {{ if eq .Data.status "SUCCESS" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Go Back</span>
                </button>
              </a>
            {{ else }}
              {{ if ne .Data.mfa_token_id "" }}
              <a href="{{ pathjoin .ActionEndpoint "/settings/mfa/test/u2f/generic" .Data.mfa_token_id }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
              {{ end }}
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "password" }}
            <form action="{{ pathjoin .ActionEndpoint "/settings/password/edit" }}" method="POST">
              <div class="row">
                <h1>Password Management</h1>
                <div class="row">
                  <div class="col s12 m6 l6">
                    <p>If you want to change your password, please provide your current password and 
                    </p>
                    <div class="input-field">
                      <input id="secret1" name="secret1" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret1">Current Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret2" name="secret2" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret2">New Password</label>
                    </div>
                    <div class="input-field">
                      <input id="secret3" name="secret3" type="password" autocorrect="off" autocapitalize="off" autocomplete="off" required />
                      <label for="secret3">Confirm New Password</label>
                    </div>
                  </div>
                </div>
              </div>
              <div class="row right">
                <button type="submit" name="submit" class="btn waves-effect waves-light navbtn active navbtn-last app-btn">
                  <i class="las la-paper-plane left app-btn-icon"></i>
                  <span class="app-btn-text">Change Password</span>
                </button>
              </div>
            </form>
          {{ end }}
          {{ if eq .Data.view "password-edit" }}
          <div class="row">
            <div class="col s12">
            {{ if eq .Data.status "SUCCESS" }}
              <h1>Password Has Been Changed</h1>
              <p>Please log out and log back in.</p>
            {{ else }}
              <h1>Password Change Failed</h1>
              <p>Reason: {{ .Data.status_reason }} </p>
              <a href="{{ pathjoin .ActionEndpoint "/settings/password" }}">
                <button type="button" class="btn waves-effect waves-light navbtn active">
                  <i class="las la-undo-alt left app-btn-icon"></i>
                  <span class="app-btn-text">Try Again</span>
                </button>
              </a>
            {{ end }}
            </div>
          </div>
          {{ end }}
          {{ if eq .Data.view "connected" }}
          <div class="row">
            <div class="col s12">
            <p>No connected accounts found.</p>
            </div>
          </div>
          {{ end }}
        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/materialize-css/js/materialize.js" }}"></script>
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/plaintext.min.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "apikeys-add") (eq .Data.view "apikeys-add-status") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/highlight.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/json.min.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/highlight.js/js/languages/plaintext.min.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-u2f") (eq .Data.view "mfa-test-u2f") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/cbor/cbor.js" }}"></script>
    {{ end }}
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "mfa-add-app") (eq .Data.view "mfa-test-app") }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_app.js" }}"></script>
    {{ end }}
    {{ if eq .Data.view "mfa-add-u2f" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_u2f.js" }}"></script>
    {{ end }}
    {{ if eq .Data.view "mfa-test-u2f" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_add_u2f.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/mfa_test_u2f.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "sshkeys-add") (eq .Data.view "gpgkeys-add") (eq .Data.view "sshkeys-view") (eq .Data.view "gpgkeys-view") }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
    {{ end }}
    {{ if or (eq .Data.view "apikeys-add") (eq .Data.view "apikeys-add-status") }}
    <script>
    hljs.initHighlightingOnLoad();
    </script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span class="app-error-text">{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
    {{ if eq .Data.view "mfa-add-u2f" }}
    <script>
function u2f_token_register(formID, btnID) {
  const params = {
    challenge: "{{ .Data.webauthn_challenge }}",
    rp_name: "{{ .Data.webauthn_rp_name }}",
    user_id: "{{ .Data.webauthn_user_id }}",
    user_name: "{{ .Data.webauthn_user_email }}",
    user_display_name: "{{ .Data.webauthn_user_display_name }}",
    user_verification: "{{ .Data.webauthn_user_verification }}",
    attestation: "{{ .Data.webauthn_attestation }}",
    pubkey_cred_params: [
      {
        type: "public-key",
        alg: -7,
      },
    ]
  };
  register_u2f_token(formID, btnID, params);
}
    </script>
    {{ end }}

    {{ if eq .Data.view "mfa-test-u2f" }}
    <script>
function u2f_token_authenticate(formID, btnID) {
  const params = {
    challenge: "{{ .Data.webauthn_challenge }}",
    timeout: {{ .Data.webauthn_timeout }},
    rp_name: "{{ .Data.webauthn_rp_name }}",
    user_verification: "{{ .Data.webauthn_user_verification }}",
    {{ if .Data.webauthn_credentials }}
    allowed_credentials: [
    {{ range .Data.webauthn_credentials }}
      {
        id: "{{ .id }}",
        type: "{{ .type }}",
        transports: [{{ .transports }}],
      },
    {{ end }}
    ],
    {{ else }}
    allowed_credentials: [],
    {{ end }}
    ext_uvm: {{ .Data.webauthn_ext_uvm }},
    ext_loc: {{ .Data.webauthn_ext_loc }},
    ext_tx_auth_simple: "{{ .Data.webauthn_tx_auth_simple }}",
  };
  authenticate_u2f_token(formID, btnID, params);
}
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/sandbox": `<!doctype html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png">
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/montserrat.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/sandbox.css" }}" />

    {{ if eq .Data.ui_options.custom_css_required "yes" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
    {{ if or (eq .Data.view "mfa_app_auth") (eq .Data.view "mfa_app_register") }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/mfa_app.css" }}" />
    {{ end }}
    {{ if eq .Data.view "password_recovery" }}
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/password.css" }}" />
    {{ end }}
  </head>
  <body class="h-full">
    <div class="app-page">
      <div class="app-content">
        <div class="app-container">
          <div class="logo-box">
            {{ if .LogoURL }}
              <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
            {{ end }}
            <h2 class="logo-txt">{{ .PageTitle }}</h2>
          </div>

          {{ if or (eq .Data.view "mfa_mixed_auth") (eq .Data.view "mfa_mixed_register") }}
          <div class="app-txt-section">
            <p>Your session requires multi-factor authentication.</p>
            {{ if eq .Data.view "mfa_mixed_register" }}
            <p>However, you do not have second factor authentication method configured.</p>
            <p>Please click the authentication methods below to proceed with the configuration.</p>
            {{ else }}
            <p>Please click the appropriate second factor authentication method to proceed further.</p>
            {{ end }}
          </div>
          <ul role="list" class="divide-y divide-primary-200">
            <li class="py-4 flex">
              <i class="las la-mobile text-2xl text-primary-500"></i>
              <div class="ml-3">
                {{ if eq .Data.view "mfa_mixed_register" }}
                <a class="app-lst-lnk" href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-register" }}"><span>Authenticator App</a>
                {{ else }}
                <a class="app-lst-lnk" href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-auth" }}">Authenticator App</a>
                {{ end }}
              </div>
            </li>
            <li class="py-4 flex">
              <i class="las la-microchip text-2xl text-primary-500"></i>
              <div class="ml-3">
                {{ if eq .Data.view "mfa_mixed_register" }}
                <a class="app-lst-lnk" href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-register" }}">Hardware Token</a>
                {{ else }}
                <a class="app-lst-lnk" href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-auth" }}">Hardware Token</a>
                {{ end }}
              </div>
            </li>
          </ul>
          {{ else if eq .Data.view "password_auth" }}
          <div>
            <form class="space-y-6"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "password-auth" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div>
                <label for="secret" class="app-inp-lbl text-center">Please provide your password</label>
                <div class="app-inp-box">
                  <div class="app-inp-prf-img">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                  </div>
                  <input id="secret" name="secret" type="password" class="app-inp-txt"
                         autocorrect="off" autocapitalize="off" spellcheck="false" autofocus required />
                </div>
              </div>

              <div class="hidden">
                <input id="sandbox_id" name="sandbox_id" type="hidden" value="{{ .Data.id }}" />
              </div>

              <div class="flex gap-4">
                <div class="flex-none">
                  <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "terminate" }}">
                    <button type="button" class="app-btn-sec">
                      <div>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                        </svg>
                      </div>
                    </button>
                  </a>
                </div>
                <div class="flex-none">
                  <button type="reset" name="reset" class="app-btn-sec">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </div>
                  </button>
                </div>

                <div class="grow">
                  <button type="submit" name="submit" class="app-btn-pri">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                    <div class="pl-2">
                      <span>Authenticate</span>
                    </div>
                  </button>
                </div>
              </div>
            </form>
          </div>
          {{ else if eq .Data.view "password_recovery" }}

          <!-- Start of Password Recovery -->
          <div>
            <form class="space-y-6"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "password-recovery" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div class="py-4">
                <label for="email" class="app-inp-lbl">Email Address</label>
                <div class="app-inp-box">
                  <input id="email" name="email" type="text"
                         class="app-inp-txt"
                         autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                         required />
                </div>
              </div>
              
              <input id="sandbox_id" name="sandbox_id" type="hidden" value="{{ .Data.id }}" />

              <div class="flex gap-4">
                <div class="flex-none">
                  <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "terminate" }}">
                    <button type="button" class="app-btn-sec">
                      <div>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                        </svg>
                      </div>
                    </button>
                  </a>
                </div>
                <div class="grow">
                  <button type="submit" name="submit" class="app-btn-pri">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                    <div class="pl-2">
                      <span>Recover</span>
                    </div>
                  </button>
                </div>
              </div>
            </form>
          </div>
          <!-- End of Password Recovery -->

          {{ else if eq .Data.view "mfa_app_auth" }}
          <div>
            <form class="space-y-6"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-auth" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div class="py-4">
                <label for="passcode" class="app-inp-lbl">Passcode</label>
                <div class="app-inp-box">
                  <input id="passcode" name="passcode" type="text"
                         class="font-['Montserrat'] app-inp-code-txt validate"
                         pattern="[0-9]{4,8}" maxlength="8"
                         title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                         autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                         required />
                </div>
              </div>
              <div class="flex gap-4">
                <div class="flex-none">
                  <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "terminate" }}">
                    <button type="button" class="app-btn-sec">
                      <div>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                        </svg>
                      </div>
                    </button>
                  </a>
                </div>
                <div class="flex-none">
                  <button type="reset" name="reset" class="app-btn-sec">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </div>
                  </button>
                </div>
                <div class="grow">
                  <button type="submit" name="submit" class="app-btn-pri">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <div class="pl-2">
                      <span>Verify</span>
                    </div>
                  </button>
                </div>
              </div>
            </form>
          </div>
          {{ else if eq .Data.view "mfa_u2f_auth" }}
          <div>
            <form id="mfa-u2f-auth-form" class="space-y-6"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-auth" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <input id="webauthn_request" name="webauthn_request" type="hidden" value="" />
              <input id="sandbox_id" name="sandbox_id" type="hidden" value="{{ .Data.id }}" />
              <div class="app-txt-section">
                <p>Insert your hardware token into a USB port. When prompted, touch,
                or otherwise trigger the hardware token.</p>
              </div>
            </form>
            <div id="mfa-u2f-auth-form-rst" class="pt-4 hidden">
              <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id }}">
                <button type="button" name="button" class="app-btn-pri">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <div class="pl-2">
                    <span>Try Again</span>
                  </div>
                </button>
              </a>
            </div>
          </div>
          {{ else if eq .Data.view "mfa_app_register" }}
          <div>
            <form class="mfa-add-app-form"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-register" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div id="token-params">
                <div class="app-txt-section">
                  <p><b>Step 1</b>: If necessary, amend the label and comment associated with the authenticator.
                    The label is what you would see in your authenticator app.
                    The comment is what you would see in this portal.
                  </p>
                </div>

                <div>
                  <label for="label" class="app-inp-lbl">Name</label>
                  <div class="app-inp-box">
                    <div class="app-inp-prf-img">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                      </svg>
                    </div>
                    <input id="label" name="label" type="text"
                           class="app-inp-txt validate"
                           value="{{ .Data.mfa_label }}" pattern="[A-Za-z0-9]{4,25}" maxlength="25"
                           title="Name should contain 4-25 characters and consists of A-Z, a-z, 0-9 characters."
                           autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                           required />
                  </div>
                </div>

                <div class="pt-4">
                  <label for="comment" class="app-inp-lbl">Comment</label>
                  <div class="app-inp-box">
                    <div class="app-inp-prf-img">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
                      </svg>
                    </div>
                    <input id="comment" name="comment" type="text"
                           class="app-inp-txt validate"
                           value="{{ .Data.mfa_comment }}" pattern="[A-Za-z0-9 -]{4,25}" maxlength="50"
                           title="Comment should contain 4-50 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                           autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                           required />
                  </div>
                </div>

                <div class="app-txt-section">
                  <p><b>Step 1a</b> (<i>optional</i>): If necessary, click
                    <a class="text-secondary-500 hover:text-primary-500" href="#advanced-setup-all" 
                      onclick="toggleAdvancedSetupMode(); return false;">here</a>
                    to customize default values.
                  </p>
                </div>

                <div id="advanced-setup-all" class="app-txt-section hidden">
                  <div class="pt-4">
                    <label for="secret" class="app-inp-lbl">Token Secret</label>
                    <div class="app-inp-box">
                      <div class="app-inp-prf-img">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                      </div>
                      <input id="secret" name="secret" type="text"
                             class="app-inp-txt validate"
                             value="{{ .Data.mfa_secret }}" pattern="[A-Za-z0-9]{10,100}" maxlength="100"
                             title="Token secret should contain 10-200 characters and consists of A-Z and 0-9 characters only."
                             autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                             required />
                    </div>
                  </div>
                  <div class="app-inp-box">
                    <select id="period" name="period" class="app-inp-sel">
                      <option value="15" {{ if eq .Data.mfa_period "15" }} selected{{ end }}>15 Seconds Lifetime</option>
                      <option value="30" {{ if eq .Data.mfa_period "30" }} selected{{ end }}>30 Seconds Lifetime</option>
                      <option value="60" {{ if eq .Data.mfa_period "60" }} selected{{ end }}>60 Seconds Lifetime</option>
                      <option value="90" {{ if eq .Data.mfa_period "90" }} selected{{ end }}>90 Seconds Lifetime</option>
                    </select>
                  </div>
                  <div class="app-inp-box">
                    <select id="digits" name="digits" class="app-inp-sel">
                      <option value="4" {{ if eq .Data.mfa_digits "4" }} selected{{ end }}>4 Digit Code</option>
                      <option value="6" {{ if eq .Data.mfa_digits "6" }} selected{{ end }}>6 Digit Code</option>
                      <option value="8" {{ if eq .Data.mfa_digits "8" }} selected{{ end }}>8 Digit Code</option>
                    </select>
                  </div>
                </div>

                <div class="app-txt-section">
                  <p><b>Step 2</b>: Open your MFA authenticator application, e.g. Microsoft/Google Authenticator, Authy, etc.,
                    add new entry and click the "Get QR" link.
                  </p>
                  <div id="mfa-get-qr-code" class="text-center">
                    <a class="text-secondary-500 hover:text-primary-500" href="#qr-code-mode" onclick="getQRCode()">Get QR Code</a>
                  </div>
                </div>
              </div>

              <div id="mfa-qr-code" class="hidden">
                <div id="mfa-qr-code-image" class="flex items-center justify-center">
                  <img src="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-barcode" .Data.code_uri_encoded }}.png" alt="QR Code" />
                </div>
                <div class="app-txt-section">
                  <p>&raquo; Can't scan? Click or copy the link below.</p>
                </div>
                <div id="mfa-no-camera-link" class="app-txt-section text-center">
                  <a class="text-secondary-500 hover:text-primary-500" href="{{ .Data.code_uri }}">No Camera Link</a>
                </div>

                <div class="app-txt-section">
                  <p><b>Step 3</b>: Enter the authentication code you see in the app and click "Add".</p>
                </div>

                <input id="email" name="email" type="hidden" value="{{ .Data.mfa_email }}" />
                <input id="type" name="type" type="hidden" value="{{ .Data.mfa_type }}" />
                <input id="barcode_uri" name "barcode_uri" type="hidden" value="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-app-barcode" }}" />

                <div class="py-4">
                  <label for="passcode" class="app-inp-lbl">Passcode</label>
                  <div class="app-inp-box">
                    <input id="passcode" name="passcode" type="text"
                           class="font-['Montserrat'] app-inp-code-txt validate"
                           pattern="[0-9]{4,8}" maxlength="8"
                           title="Authentication code should contain 4-8 characters and consists of 0-9 characters."
                           autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off"
                           required />
                  </div>
                </div>

                <div class="flex gap-4">
                  <div class="grow">
                    <button type="submit" name="submit" class="app-btn-pri">
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
                      </svg>
                      <div class="pl-2">
                        <span>Add</span>
                      </div>
                    </button>
                  </div>
                </div>
              </div>

            </form>
          </div>
          {{ else if eq .Data.view "mfa_u2f_register" }}
          <div>
            <form id="mfa-add-u2f-form" class="space-y-6"
                  action="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "mfa-u2f-register" }}"
                  method="POST"
                  autocomplete="off"
                  >
              <div class="space-y-6 text-lg leading-7 text-primary-600">
                <p>Please insert your U2F (USB, NFC, or Bluetooth) Security Key, e.g. Yubikey.</p>
                <p>Then, please click "Register" button below.</p>
              </div>
              <input class="hidden" id="webauthn_register" name="webauthn_register" type="text" />
              <input class="hidden" id="webauthn_challenge" name="webauthn_challenge" type="text" value="{{ .Data.webauthn_challenge }}" />

              <div>
                <label for="comment" class="app-inp-lbl">Name your token (optional)</label>
                <div class="app-inp-box">
                  <div class="app-inp-prf-img">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
                    </svg>
                  </div>
                  <input id="comment" name="comment" type="text"
                         class="app-inp-txt validate"
                         pattern="[A-Za-z0-9 -]{4,25}" maxlength="25"
                         title="A comment should contain 4-25 characters and consists of A-Z, a-z, 0-9, space, and dash characters."
                         autocorrect="off" autocapitalize="off" spellcheck="false" autocomplete="off" />
                </div>
              </div>

              <div class="flex gap-4">
                <div class="flex-none">
                  <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id "terminate" }}">
                    <button type="button" class="app-btn-sec">
                      <div>
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                        </svg>
                      </div>
                    </button>
                  </a>
                </div>
                <div class="flex-none">
                  <button type="reset" name="reset" class="app-btn-sec">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </div>
                  </button>
                </div>

                <div class="grow">
                  <button id="mfa-add-u2f-button" type="button" name="action" class="app-btn-pri"
                    onclick="u2f_token_register('mfa-add-u2f-form', 'mfa-add-u2f-button'); return false;">
                    <div>
                      <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                    <div class="pl-2">
                      <span>Register</span>
                    </div>
                  </button>
                </div>
              </div>
            </form>

            <div id="mfa-add-u2f-form-rst" class="hidden">
              <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id }}">
                <button type="button" name="button" class="app-btn-pri">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <div class="pl-2">
                    <span>Try Again</span>
                  </div>
                </button>
              </a>
            </div>
          </div>
          {{ else if eq .Data.view "terminate" }}
          <div class="app-txt-section">
            <p>{{ .Data.error }}.</p>
          </div>
          <div class="flex gap-4">
            <div class="grow">
              <a href="{{ pathjoin .ActionEndpoint "login" }}">
                <button type="button" class="app-btn-pri">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <div class="pl-2">
                    <span>Start Over</span>
                  </div>
                </button>
              </a>
            </div>
          </div>
          {{ else if eq .Data.view "error" }}
          <div class="app-txt-section">
            <p>Your session failed to meet authorization requirements.</p>
            <p>{{ .Data.error }}.</p>
          </div>
          <div class="flex gap-4">
            <div class="grow">
              <a href="{{ pathjoin .ActionEndpoint "sandbox" .Data.id }}">
                <button type="button" class="app-btn-pri">
                  <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <div class="pl-2">
                    <span>Try Again</span>
                  </div>
                </button>
              </a>
            </div>
          </div>
          {{ else }}
          <div class="app-txt-section">
            <p>The {{ .Data.view }} view is unsupported.</p>
          </div>
          {{ end }}

        </div>
      </div>
    </div>

    <!-- Optional JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/sandbox.js" }}"></script>

    {{ if eq .Data.ui_options.custom_js_required "yes" }}
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
    {{ if eq .Data.view "mfa_app_register" }}
    <!-- App Authentication Registration Scripts -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/sandbox_mfa_add_app.js" }}"></script>
    {{ end }}
    {{ if or (eq .Data.view "mfa_u2f_register") (eq .Data.view "mfa_u2f_auth") }}
    <!-- U2F Authentication Scripts -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/cbor/cbor.js" }}"></script>
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/sandbox_mfa_u2f.js" }}"></script>
    {{ end }}

    {{ if eq .Data.view "mfa_u2f_register" }}
    <script>
    function u2f_token_register(formID, btnID) {
      const params = {
        challenge: "{{ .Data.webauthn_challenge }}",
        rp_name: "{{ .Data.webauthn_rp_name }}",
        user_id: "{{ .Data.webauthn_user_id }}",
        user_name: "{{ .Data.webauthn_user_email }}",
        user_display_name: "{{ .Data.webauthn_user_display_name }}",
        user_verification: "{{ .Data.webauthn_user_verification }}",
        attestation: "{{ .Data.webauthn_attestation }}",
        pubkey_cred_params: [
          {
            type: "public-key",
            alg: -7,
          },
        ]
      };
      register_u2f_token(formID, btnID, params);
    }
    </script>
    {{ end }}
    {{ if eq .Data.view "mfa_u2f_auth" }}
    <script>
    function u2f_token_authenticate(formID) {
      const params = {
        challenge: "{{ .Data.webauthn_challenge }}",
        timeout: {{ .Data.webauthn_timeout }},
        rp_name: "{{ .Data.webauthn_rp_name }}",
        user_verification: "{{ .Data.webauthn_user_verification }}",
        {{- if .Data.webauthn_credentials }}
        allowed_credentials: [
        {{- range .Data.webauthn_credentials }}
          {
            id: "{{ .id }}",
            type: "{{ .type }}",
            transports: [{{ range .transports }}"{{ . }}",{{ end }}],
          },
        {{- end }}
        ],
        {{ else }}
        allowed_credentials: [],
        {{end -}}
        ext_uvm: {{ .Data.webauthn_ext_uvm }},
        ext_loc: {{ .Data.webauthn_ext_loc }},
        ext_tx_auth_simple: "{{ .Data.webauthn_tx_auth_simple }}",
      };
      authenticate_u2f_token(formID, params);
    }

    window.addEventListener("load", u2f_token_authenticate('mfa-u2f-auth-form'));
    </script>
    {{ end }}
    {{ if .Message }}
    <script>
    var toastHTML = '<span>{{ .Message }}</span><button class="btn-flat toast-action" onclick="M.Toast.dismissAll();">Close</button>';
    toastElement = M.toast({
      html: toastHTML,
      classes: 'toast-error'
    });
    const appContainer = document.querySelector('.app-card-container')
    appContainer.prepend(toastElement.el)
    </script>
    {{ end }}
  </body>
</html>`,
	"basic/apps_aws_sso": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/apps_aws_sso.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content">
        <div class="app-container">
          <div class="logo-col-box justify-center">
            {{ if .LogoURL }}
              <div>
                <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
              </div>
            {{ end }}
            <div>
              <h2 class="logo-col-txt">{{ .PageTitle }}</h2>
            </div>
          </div>

          {{ if gt .Data.role_count 0 }}
            <div class="pb-4 pt-4">
              <p class="app-inp-lbl">Assume the following roles on the associated AWS accounts.</p>
            </div>

            <div class="flex flex-col">
              <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
                <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
                  <table class="min-w-full divide-y divide-gray-300">
                    <thead>
                      <tr>
                        <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-primary-700 sm:pl-6 md:pl-0">Role Name</th>
                        <th scope="col" class="py-3.5 px-3 text-left text-sm font-semibold text-primary-700">Account ID</th>
                      </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                      {{ range .Data.roles }}
                        <tr>
                          <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-primary-700 sm:pl-6 md:pl-0 leading-none">
                            <span>{{ brsplitline .Name }}</span>
                          </td>
                          <td class="whitespace-nowrap py-4 px-3 text-sm text-primary-500">{{ .AccountID }}</td>
                        </tr>
                      {{ end }}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          {{ else }}
            <div class="pb-4 pt-4">
              <p class="app-inp-lbl">Your user identity has no roles associated with AWS accounts.</p>
            </div>
          {{ end }}


          <div class="flex flex-wrap {{ if gt .Data.role_count 0 }}pt-6{{ end }} justify-center gap-4">
            <div id="forgot_username_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/portal" }}">
                <i class="las la-layer-group"></i>
                <span class="text-lg">Portal</span>
              </a>
            </div>
            <div id="contact_support_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/logout" }}">
                <i class="las la-times-circle"></i>
                <span class="text-lg">Sign Out</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/apps_aws_sso.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
	"basic/apps_mobile_access": `<!DOCTYPE html>
<html lang="en" class="h-full bg-blue-100">
  <head>
    <title>{{ .MetaTitle }} - {{ .PageTitle }}</title>
    <!-- Required meta tags -->
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="{{ .MetaDescription }}" />
    <meta name="author" content="{{ .MetaAuthor }}" />
    <link rel="shortcut icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="icon" href="{{ pathjoin .ActionEndpoint "/assets/images/favicon.png" }}" type="image/png" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/google-webfonts/roboto.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/line-awesome/line-awesome.css" }}" />
    <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/apps_mobile_access.css" }}" />
    {{ if eq .Data.ui_options.custom_css_required "yes" }}
      <link rel="stylesheet" href="{{ pathjoin .ActionEndpoint "/assets/css/custom.css" }}" />
    {{ end }}
  </head>

  <body class="h-full">
    <div class="app-page">
      <div class="app-content">
        <div class="app-container">
          <div class="logo-col-box">
            {{ if .LogoURL }}
              <div>
                <img class="logo-img" src="{{ .LogoURL }}" alt="{{ .LogoDescription }}" />
              </div>
            {{ end }}
            <div>
              <h2 class="logo-col-txt">{{ .PageTitle }}</h2>
            </div>
          </div>
          <div>
            <p class="app-inp-lbl">Scan the below QR code and follow the link to perform one-time passwordless login.</p>
          </div>

          <div class="flex flex-wrap pt-6 justify-center gap-4">
            <div id="forgot_username_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/portal" }}">
                <i class="las la-layer-group"></i>
                <span class="text-lg">Portal</span>
              </a>
            </div>
            <div id="contact_support_link">
              <a class="text-primary-600" href="{{ pathjoin .ActionEndpoint "/logout" }}">
                <i class="las la-times-circle"></i>
                <span class="text-lg">Sign Out</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- JavaScript -->
    <script src="{{ pathjoin .ActionEndpoint "/assets/js/apps_mobile_access.js" }}"></script>
    {{ if eq .Data.ui_options.custom_js_required "yes" }}
      <script src="{{ pathjoin .ActionEndpoint "/assets/js/custom.js" }}"></script>
    {{ end }}
  </body>
</html>`,
}
