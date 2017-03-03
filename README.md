Implementation of the Battle.net Mobile Authenticator in PHP.

# Usage

You can either request a new serial, generate codes from an existing one, or use your restore code to obtain your secret key.

## Request New Serial

You must call the script with the desired region passed in parameter :

	php php-bma.php new EU

Valid region are `EU` or `US`

Before starting to give you a code, the program will print the new serial and secret kez on screen. Write them down and register your Authenticator with Battle.net

## Generate Codes From An Existing Serial

Just pass your serial and secret key on the command line :

	php php-bma.php generate serial secret_key

## Use A Restore Code To Obtain A Secret Key

Just pass your serial and restore code on the command line :

	php php-bma.php restore serial restore_code

# Who use it ?

I'm using this on a little project of mine, an [Online Authenticator for Battle.Net](http://authenticator.me). It is actually in Beta, but I'm planning on launching it soon.

<a href='https://github.com/ymback'>ymback</a> has created a <a href='https://github.com/ymback/Battle.net-Authenticator-Online'>repo</a>, using this as a library on his [Battle.Net Authenticator Online](https://myauth.us). A Chinese-based website.

# Todo

* Sanitize inputs
* Unit tests
* Provide the possiblity to save Serial and Secret key to file and / or database

