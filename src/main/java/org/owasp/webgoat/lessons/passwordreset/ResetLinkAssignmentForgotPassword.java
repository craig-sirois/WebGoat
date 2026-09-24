/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.passwordreset;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword extends AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private String webWolfHost;
  private String webWolfPort;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    
    // Extract host from request for validation purposes only
    String requestHost;
    try {
      URI uri = new URI(request.getRequestURL().toString());
      requestHost = uri.getHost();
      int port = uri.getPort();
      // Include port in host string if present and not default
      if (port != -1 && port != 80 && port != 443) {
        requestHost = requestHost + ":" + port;
      }
    } catch (URISyntaxException e) {
      return failed(this).output("Invalid request URL").build();
    }
    
    // Validate against expected WebWolf host configurations using exact match
    // This prevents bypasses like "evil.com:9090" or "evil.com/localhost"
    boolean isWebWolfRequest = false;
    
    // Build list of acceptable hosts
    String expectedWebWolfHost1 = webWolfHost + ":" + webWolfPort;
    String expectedWebWolfHost2 = webWolfHost;
    
    // Check exact match
    if (requestHost.equals(expectedWebWolfHost1) || requestHost.equals(expectedWebWolfHost2)) {
      isWebWolfRequest = true;
    }
    
    // Also accept localhost as equivalent to 127.0.0.1 for local development/testing
    if (!isWebWolfRequest && "127.0.0.1".equals(webWolfHost)) {
      String localhostWithPort = "localhost:" + webWolfPort;
      if (requestHost.equals(localhostWithPort) || requestHost.equals("localhost")) {
        isWebWolfRequest = true;
      }
    }
    
    if (ResetLinkAssignment.TOM_EMAIL.equals(email) && isWebWolfRequest) {
      ResetLinkAssignment.userToTomResetLink.put(getWebSession().getUserName(), resetLink);
      // Use configured WebWolf host for callback, not request host
      // This prevents SSRF to arbitrary hosts
      String webWolfHostWithPort = webWolfHost + ":" + webWolfPort;
      fakeClickingLinkEmail(webWolfHostWithPort, resetLink);
    } else {
      try {
        // For regular emails, use the validated request host
        sendMailToUser(email, requestHost, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String host, String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("http://%s/PasswordReset/reset/reset-password/%s", host, resetLink),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // don't care
    }
  }
}
