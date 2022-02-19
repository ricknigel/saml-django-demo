import os

from django.conf import settings
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings


def load_settings():
    return {
        'strict': True,
        'debug': True,
        'sp': {
            'entityId': os.getenv('SP_ENTITY_ID'),
            'assertionConsumerService': {
                'url': os.getenv('SP_ACS_URL'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            },
            'singleLogoutService': {
                'url': '',
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'x509cert': '',
            'privateKey': ''
        },
        'idp': {
            'entityId': os.getenv('IDP_ENTITY_ID'),
            'singleSignOnService': {
                'url': os.getenv('IDP_SSO_URL'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
            'singleLogoutService': {
                'url': '',
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
            'x509cert': os.getenv('IDP_CERT')
        }
    }


def init_saml_auth(req):
    """
    SAMLクライアント初期化
    """
    settings_data = load_settings()
    auth = OneLogin_Saml2_Auth(req, settings_data)
    return auth


def prepare_django_request(request):
    """
    SAMLクライアント初期化パラメータ
    """
    result = {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META['SERVER_PORT'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
        'query_string': request.META['QUERY_STRING']
    }
    return result


def index(request):
    """
    トップページ
    """

    attributes = False

    if 'samlUserdata' in request.session:
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    return render(request, 'index.html', {'attributes': attributes})


@csrf_exempt
def sso(request):
    """
    SAML認証要求
    """
    req = prepare_django_request(request)
    auth = init_saml_auth(req)

    return HttpResponseRedirect(auth.login())


@csrf_exempt
def acs(request):
    """
    SAML認証応答 アサーション検証
    """
    req = prepare_django_request(request)
    auth = init_saml_auth(req)

    request_id = None
    if 'AuthNRequestID' in request.session:
        request_id = request.session['AuthNRequestID']

    auth.process_response(request_id=request_id)
    errors = auth.get_errors()

    if not errors:
        if 'AuthNRequestID' in request.session:
            del request.session['AuthNRequestID']
        request.session['samlUserdata'] = auth.get_attributes()
        request.session['samlNameId'] = auth.get_nameid()
        request.session['samlNameIdFormat'] = auth.get_nameid_format()
        request.session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
        request.session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
        request.session['samlSessionIndex'] = auth.get_session_index()

    return HttpResponseRedirect(auth.redirect_to('/'))


def metadata(request):
    """
    SPメタデータ出力
    """
    saml_settings = OneLogin_Saml2_Settings(
        settings=None,
        custom_base_path=settings.SAML_FOLDER,
        sp_validation_only=True
    )
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        return HttpResponse(content=metadata, content_type='text/xml')
    else:
        return HttpResponseServerError(content=','.join(errors))
