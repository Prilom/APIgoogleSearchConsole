# -*- coding: utf-8 -*-
import csv
import sys
import os
import flask
import requests
from flask import jsonify
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import httplib2
# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/webmasters.readonly']
API_SERVICE_NAME = 'searchconsole'
API_VERSION = 'v1'

site_url = 'https://hannun.com/'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = '192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf'
def execute_request_total_pages(service, property_uri, request):
    """Executes a searchAnalytics.query request.
    Args:
      service: The searchconsole service to use when executing the query.
      property_uri: The site or app URI to request data for.
      request: The request to be executed.
    Returns:
      An array of response rows.
    """
    return service.searchanalytics().query(siteUrl=property_uri, body=request).execute()


@app.route('/errors')
def get_errors():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Carga las credenciales de la sesión
    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])

    # Crea el servicio de la API de Search Console
    search_console_service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Obtén la lista de url de la cuenta
    site_list = search_console_service.sites().list().execute()
    # Filtra los sitios verificados
    verified_sites_urls = [s['siteUrl'] for s in site_list['siteEntry']
                           if s['permissionLevel'] != 'siteUnverifiedUser'
                           and s['siteUrl'].startswith('http')]
    
    request = {
        "startDate": '2017-04-01',
        "endDate": '2023-05-01',
        "dimensions": ["page"],
        "rowLimit": 500
    }
    response_api = execute_request_total_pages(search_console_service, site_url, request)
    csv_filename = 'pages_404.csv'
    
    rows = response_api['rows']
    total_rows = len(rows)

    def generate():
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['URL'])  # Escribir encabezado del CSV

            for index, item in enumerate(rows):
                page = item['keys'][0]  # Obtén la URL de la página
                payload = {
                    'inspectionUrl': page,
                    'siteUrl': site_url
                } 
                response = search_console_service.urlInspection().index().inspect(body=payload).execute()
                if response['inspectionResult']['indexStatusResult']['pageFetchState'] == 'NOT_FOUND':
                    writer.writerow([page])  # Escribir URL en una fila

                # Calcular el progreso actual
                progress = (index + 1) / total_rows * 100

                # Enviar la actualización al cliente
                print(f"Progress: {progress}%", end='\r')
                sys.stdout.flush()

    # Establecer el encabezado de respuesta para eventos de tipo "text/event-stream"
    return flask.Response(generate(), mimetype='text/event-stream')
  

    return {'msg': response_api}
@app.route('/')
def index():
  return print_index_table()


@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')
  
  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])
  print('Credentials loaded successfully:', credentials)
  # Retrieve list of properties in account
  search_console_service = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)
  print('Search Console service created successfully:', search_console_service)
  site_list = search_console_service.sites().list().execute()
  # Filter for verified URL-prefix websites.
  verified_sites_urls = [s['siteUrl'] for s in site_list['siteEntry']
                        if s['permissionLevel'] != 'siteUnverifiedUser'
                        and s['siteUrl'].startswith('http')]

  # Print the sitemaps for all websites that you can access.
  results = '<!DOCTYPE html><html><body><table><tr><th>Verified site</th><th>Sitemaps</th></tr>'
  for site_url in verified_sites_urls:

    # Retrieve list of sitemaps submitted
    sitemaps = search_console_service.sitemaps().list(siteUrl=site_url).execute()
    results += '<tr><td>%s</td>' % (site_url)

    # Add a row with the site and the list of sitemaps
    if 'sitemap' in sitemaps:
      sitemap_list = "<br />".join([s['path'] for s in sitemaps['sitemap']])
    else:
      sitemap_list = "<i>None</i>"
    results += '<td>%s</td></tr>' % (sitemap_list)

  results += '</table></body></html>'

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  flask.session['credentials'] = credentials_to_dict(credentials)

  return results



@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/errors">Error 404</a></td>'+
          '<td>comprueba los errores 404. ' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')


if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)