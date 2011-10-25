Implementation of the Battle.net Mobile Authenticator in PHP.

# Usage

You can either request a new serial or re-use an existing one.

## New serial

You must call the script with the desired region passed in parameter :

	php php-bna.php EU

Valid region are `EU` or `US`

Before starting to give you a code, the program will print the new serial and secret kez on screen. Write them down and register your Authenticator with Battle.net

## Existing serial

Just pass your serial and secret kez on the command line :

	php php-bna.php serial secret_key
	
# Who use it ?

I'm using this on a little project of mine, an [Online Authenticator for Battle.Net](http://authenticator.gloump.net/). It is actually in Beta, but I'm planning on launching it soon.

# Todo

* Sanitize inputs
* Unit tests
* Save Serial and Secret key to file and / or database
