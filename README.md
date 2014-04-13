otp-pwman
=====

Local password manager using a One-Time-Pad strategy for encryption

Note: Due to clipboard support I current only support windows. It likely can ported to other
      platforms in a straightforward fashion.

The program allows you to generate and track multiple high-entropy passwords for use on
	whatever sites you happen to have login information for. These passwords are generated
	using a cryptographically-safe random number generator (see crypto/rand). Along with
	clipboard integration, it allows you to never have to care what your passwords really
	are. Instead, you simply have to remember your master password(s) in order to access
	the randomly generated passwords. This is "safe" because the program runs locally, never
	interacting with any device but the computer it is run on.

Since the passwords entered in remote sites are literally random, they are free from any
	attack other than brute-force. But even that is of minimal concern: each character in the
	password can be more than 90 different values, meaning that for even just a 6 letter password
	there are more than 1/2 trillion unique possibilities. Even considering the birthday paradox
	that's pretty safe (most likely safer than all of your current passwords, unless you REALLY
	care about security).
	
You also have to specify a salt, but that doesn't have to be as secure/secret as your password.
	Hard-coding the value for the salt is probably safe, so feel free to do so.

More technical information:

	A master password is used to create a cryptographic hash via pbkdf2.
	Bits from this hash are used to determine where the data will come from for the one-time-pad.
	The one-time-pad is used to encrypt both passwords and password labels (or keys), but NOT the
		structure of the save file. The effect of this is that multiple master passwords may be
		used at the same time for the same password file with the simple restriction that passwords
		tracked using a different master password will not have a correct label nor password value.

Right now I use data from four english works of literature, downloaded from Project Guttenburg. I
	choose "Moby Dick", "Beowulf", "Book of 1000 Mythological Characters Briefly Described", and
	the Kama Sutra. The hash bits are used to switch between the works of literature (as well as
	determining the starting position in these files for the pad) so that the bytes have a good
	amount of reproduceable entropy without relying on any sort of algorithm which can be broken.
	Statistical analysis would probably be useful in cracking this, but since all data is stored
	locally an attacker would need to access your computer files first; if they can do that you
	have bigger probems anyway.
	
The program is also flash-drive portable, but you must be prepared to recover all of your accounts
	in the event that your drive is lost or stolen.


	
	
	
	
	
	
	
	
	
IMPORTANT:
	If any of this is wrong, please let me know immediately so I don't look silly. Pull requests are
very welcome.

This software is currently licensed under GPLv3, but I reserve the right to alter the license at any
	time for any reason (including specific individuals).












