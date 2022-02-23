from django.http import HttpResponseRedirect


def login_required(f):
    def _f(request, *args):
        email = request.session.get('email', '')
        if not email:
            return HttpResponseRedirect('/timeout')
        else:
            return f(request, *args)
    return _f
