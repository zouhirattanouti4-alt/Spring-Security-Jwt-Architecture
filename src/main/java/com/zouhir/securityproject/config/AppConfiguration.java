package com.zouhir.securityproject.config;


import com.zouhir.securityproject.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AppConfiguration {
    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService(){
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found!"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }

}









/*                          ---------------authenticationProvider------------

Le rôle de la ligne http.authenticationProvider(authenticationProvider) est de brancher le cerveau décisionnel qui vérifie l'identité d'un utilisateur en comparant ses informations avec la base de données.
Sans ce composant, Spring Security est incapable de vérifier si un mot de passe est correct ou si le compte existe réellement.
1. Le Problème Fondamental : La diversité des méthodes de connexion
Dans le monde réel, un utilisateur peut s'authentifier de dizaines de façons différentes :
Avec un email et mot de passe stockés dans MySQL ou PostgreSQL.
Via un annuaire d'entreprise (LDAP / Active Directory).
Avec un compte Google / GitHub (OAuth2).
Par certificat numérique ou empreinte.
Spring Security ne peut pas deviner à l'avance la technique que vous utilisez. Il a donc conçu un système modulaire : l'interface AuthenticationProvider.
Chaque façon de s'authentifier possède son propre Provider. La méthode http.authenticationProvider(...) sert à dire à Spring : "Pour cette application, voici le moteur de vérification officiel que tu dois utiliser".
2. La Nature de AuthenticationProvider
Techniquement, AuthenticationProvider est une interface standard de Spring Security. Dans une architecture classique (email/mot de passe avec base de données), on utilise son implémentation prête à l'emploi : DaoAuthenticationProvider (DAO = Data Access Object).
Ce DaoAuthenticationProvider a besoin de deux ingrédients obligatoires pour fonctionner :
Un détective (Le UserDetailsService) : L'outil qui sait comment chercher l'utilisateur en base de données par son email/username (notre fameuse fonction lambda vue précédemment).
Un décodeur (Le PasswordEncoder) : L'outil mathématique capable de comparer un mot de passe en clair avec un mot de passe haché (comme BCrypt).

 */