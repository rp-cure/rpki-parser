# READ ME
Um das Tool nutzen zu können muss man eine modifierte Version von asn1crypto installieren.
Dazu muss Python pip installiert sein. Installieren über pip install ./asn1crypto-1.5.2.tar.gz (Falls asn1crypto vorher schon installiert war muss es natürlich erst deinstalliert werden)
Danach einfach parsing.py ausführen. Dort wird gezeigt, wie man ein RPKI Objekt parsen kann. Der Ordner enthält ein Beispielobjekt für jeden (relevanten) Objekttypen in der RPKI. Am einfachsten ist es vermutlich, sich die geparsten Objekte im Debugger anzuschauen und damit rumzuspielen.

Ein weiteres Tool zum Anschauen von den RPKI Objekten ist lapo https://lapo.it/asn1js/#
Einfach eins der Objekte auswählen und anschauen. Achtung, die Objekte sind relativ komplex 
