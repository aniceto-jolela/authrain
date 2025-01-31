# Django authentication rain

Authentication rain is a website to diversify several authentication using **Django** and **Firebase**.

Used Technologies:
- django
- firebase
- render
- crispy-forms
- crispy-bulma

This website aims to make various types authentication and giving tips on good data security practices. When creating this website was thought of `backend` and in the authentication of Firebase Email / password not on the `front-end`. So I hope you have a good experience on the `cliete side`.

#### Types of Authentication
1. user / password
2. email / password

Here is the [site]() link for those who want to take a test.

I also made the code available on [Github](https://github.com/aniceto-jolela/django-authentication-rain), for those interested in reusing one of the authentication or studying the code.

If you are looking for a Django project that manages image or privacy and user privileges you can access this [link](https://django-crud-dh2q.onrender.com/) | [repository](https://github.com/aniceto-jolela/django-crud);

Or if you are looking for Full-Stack-Application with React / Django, go to this [link](https://full-stack-application-two.vercel.app/) | [github](https://github.com/aniceto-jolela/full-stack-application)

[Download the video]()

#
# configure
- Template pack
```shell
    pip install crispy-bulma
``` 
- Server-side Firebase integration
```shell
    pip install firebase-admin pyrebase4
```
- Create a Firebase Project
1. Go to the [Firebase Console](https://console.firebase.google.com/).
2. Create a new project (or use an existing one).
3. Go to Project settings > Service accounts.
4. Generate a new private key by clicking Generate new private key. This will download a  `JSON` file with credentials to access `Firebase Admin SDK`.

- Install Dotenv
```shell
    pip install python-dotenv
```
- Requirements
```shell
    pip freeze > requirements.txt
```
- Gunicorn
```shell
    pip install gunicorn
```


