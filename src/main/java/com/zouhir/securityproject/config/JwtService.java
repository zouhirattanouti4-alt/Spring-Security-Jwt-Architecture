package com.zouhir.securityproject.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secret_key;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    public Date extractIssuedAt(String token){
        return extractClaim(token, Claims::getIssuedAt);
    }
    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        String username = userDetails.getUsername();
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Key getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secret_key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}




















/*                              extractAllClaims(String token)


1. Le Contexte Global (Vue d'Architecte)
Ton application utilise des JWT (JSON Web Tokens) pour authentifier les utilisateurs.
Un JWT est une chaîne de caractères sécurisée envoyée par le client (comme un navigateur) à chaque requête.
Ce jeton contient des Claims (revendications ou affirmations en français). Ce sont les informations de l'utilisateur (son identifiant, son rôle, la date d'expiration du jeton).
Le rôle de cette méthode extractAllClaims est de prendre ce jeton, de vérifier que personne ne l'a falsifié, et de lire toutes les informations qu'il contient.



2. Anatomie de la Méthode (Ligne par Ligne)


private Claims extractAllClaims(String token)
private : Un choix d'architecture crucial. Cette méthode fait le "sale boulot" technique en interne. On la cache (private) pour que le reste de l'application n'y ait pas accès directement. L'architecte expose uniquement des méthodes propres comme extractUsername(token).
Claims : C'est le type de retour. C'est un objet (provenant de la bibliothèque de sécurité) qui agit comme une boîte contenant toutes les données de l'utilisateur.
String token : C'est l'argument d'entrée, la fameuse chaîne de caractères envoyée par le client.



3. Le "Design Pattern" utilisé : Le Builder Pattern
Avant d'expliquer les lignes à l'intérieur, remarque la structure avec les points verticaux : .parserBuilder().setSigningKey().build().
En architecture, cela s'appelle le Builder Pattern (Patron de conception Constructeur). Au lieu de créer un objet complexe en une seule ligne incompréhensible, on le construit étape par étape, comme un menu où l'on choisit ses options l'une après l'autre.
Voici le détail de chaque étape de la chaîne :


Étape 1 : Jwts
C'est la classe principale (la boîte à outils) de la bibliothèque Java JWT. C'est le point d'entrée pour tout ce qui concerne la création ou la lecture des jetons.


Étape 2 : .parserBuilder()
Cette méthode dit à la bibliothèque : "Je veux créer un outil capable de lire et de décortiquer (analyser/parser) un jeton". À ce stade, l'outil est vide et n'est pas encore prêt.


Étape 3 : .setSigningKey(getSignInKey())
C'est l'étape la plus importante pour la sécurité.
Un JWT est signé numériquement par le serveur avec une clé secrète pour éviter la fraude. Si un pirate modifie son rôle dans le jeton pour devenir "Admin", la signature devient invalide.
getSignInKey() récupère cette clé secrète du serveur.
.setSigningKey(...) donne cette clé à notre outil d'analyse. L'outil sait maintenant quelle clé utiliser pour vérifier si le jeton est authentique ou s'il a été truqué.


Étape 4 : .build()
Cette méthode finalise la configuration. Elle assemble toutes les pièces (l'outil d'analyse + la clé secrète) et fabrique officiellement l'objet de type JwtParser (l'analyseur).


Étape 5 : .parseClaimsJws(token)
Maintenant que notre analyseur est prêt et sécurisé, on lui donne le jeton reçu du client (token).
L'analyseur fait deux choses :
Il vérifie mathématiquement la signature avec la clé secrète. Si le jeton est expiré ou falsifié, le code s'arrête immédiatement ici et lève une erreur (exception).
Si tout est correct, il décode la chaîne de caractères pour la transformer en un objet Java lisible.


Étape 6 : .getBody()
Un JWT est composé de trois parties : l'en-tête (Header), le corps (Body/Payload), et la signature.
L'en-tête contient des données techniques inutiles pour nous.
Le corps (Body) contient les données de l'utilisateur (les fameux Claims).
.getBody() extrait uniquement cette partie utile et la retourne sous forme d'un objet Claims.



 */



/*                              getSignInKey


 Pourquoi cette méthode existe ?
Pour signer un JWT (ou vérifier sa signature), l'application ne peut pas utiliser une simple chaîne de caractères (un String comme "mon_secret_123"). Les algorithmes de sécurité exigeants comme HMAC-SHA nécessitent un objet cryptographique spécialisé (de type Key).
Le rôle de cette méthode est de transformer une configuration textuelle (SECRET_KEY) en un outil de sécurité standardisé (Key) utilisable par la bibliothèque cryptographique.



2. Analyse ligne par ligne et mot par mot


private Key getSignInKey()
private : Encapsulation stricte. La clé secrète ne doit jamais fuiter en dehors de cette classe JwtService. Aucune autre partie de l'application n'a besoin de manipuler cet objet.
Key : C'est l'interface de base de Java (java.security.Key) pour toutes les clés cryptographiques. L'architecte utilise l'interface Key (générique) plutôt qu'une implémentation précise pour garder le code flexible. Si l'on change d'algorithme demain, le type de retour reste le même.


byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
SECRET_KEY : C'est une chaîne de caractères (String) stockée généralement dans ton fichier de configuration (application.properties ou .env). Pour des raisons de transport et de stockage, cette clé est encodée en Base64 (un format qui transforme des données binaires en texte lisible avec des lettres et des chiffres).
Decoders.BASE64.decode(...) : C'est l'opération inverse. On prend la chaîne de caractères et on la "décode" pour récupérer les données brutes d'origine.
byte[] : Un tableau d'octets. En informatique de bas niveau, un octet (byte) est une suite de 8 bits (des 0 et des 1). C'est la forme brute de la donnée dont l'algorithme a besoin.
keyBytes : Le nom de la variable locale qui stocke temporairement ces octets en mémoire.


return Keys.hmacShaKeyFor(keyBytes);
Keys : Une classe utilitaire de la bibliothèque JJWT (un "Factory Pattern" ou usine) qui permet de générer facilement des clés de sécurité.
hmacShaKeyFor(...) : C'est la méthode magique. Elle prend ton tableau d'octets (keyBytes) et vérifie s'il est assez long et robuste. Ensuite, elle l'enveloppe dans un objet qui implémente l'interface Key en spécifiant que cette clé est dédiée à l'algorithme HMAC-SHA (un algorithme de hachage ultra-sécurisé pour vérifier l'intégrité des données).



 */


/*                                     extractClaim()



Le Découpleur Universel (Le patron Strategy)
Auparavant, la méthode extractAllClaims récupérait toutes les données d'un coup dans un gros bloc (Claims).
Le rôle de extractClaim est d'agir comme un guichet unique et universel. Au lieu de créer une méthode spécifique pour chaque information (comme extractUsername, extractExpirationDate, extractRoles, etc.), l'architecte crée une seule méthode générique.
Elle dit au reste de l'application : "Donne-moi le jeton, et dis-moi sous quelle forme ou quelle information précise tu veux extraire. Je m'occupe du reste." Cela découple complètement la plomberie technique (décoder le jeton) de la logique métier (ce qu'on veut lire dedans).



2. Analyse ligne par ligne et mot par mot (Les détails)


public <T> T extractClaim(...)
public : Contrairement aux deux méthodes précédentes qui étaient private, celle-ci est exposée au reste de l'application (les contrôleurs, les filtres de sécurité). C'est l'interface officielle de ton service.
<T> : C'est l'un des concepts les plus puissants en architecture Java : la Généricité. Le <T> est un jeton de substitution pour un type de donnée inconnu à l'avance. Ce T s'adaptera automatiquement. Si tu cherches le nom de l'utilisateur, T deviendra un String. Si tu cherches la date d'expiration, T deviendra un Date.
T (juste avant le nom de la méthode) : C'est le type de retour. La méthode promet de renvoyer exactement le type de donnée que l'appelant a demandé.


(String token, Function<Claims, T> claimsResolver)
String token : Le jeton brut reçu du client.
Function<Claims, T> claimsResolver : C'est une interface fonctionnelle introduite en Java 8. Elle représente une fonction ou un comportement passé en paramètre.
Claims : C'est ce que la fonction prend en entrée (la grosse boîte de données).
T : C'est ce que la fonction va extraire et retourner en sortie.
En gros : Tu ne passes pas seulement de la donnée à cette méthode, tu lui passes une instruction de traitement (une fonction lambda).


final Claims claims = extractAllClaims(token);
final : Une bonne pratique d'architecte. Cela garantit que la variable claims est immuable (on ne peut pas la réassigner par erreur plus bas dans le code), ce qui sécurise le flux de données.
extractAllClaims(token) : C'est la première méthode privée que nous avons analysée. On réutilise ce composant pour valider le jeton et obtenir toutes les données brutes.


return claimsResolver.apply(claims);
.apply(claims) : On exécute l'instruction de traitement (la fonction lambda) que l'utilisateur nous a passée en paramètre, en lui injectant la boîte de claims qu'on vient de récupérer.
return : On renvoie le résultat de cette extraction directement à l'appelant
 */