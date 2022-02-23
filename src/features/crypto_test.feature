Feature: testing crypto API

  @report
  Scenario: Get the server's time
    Given an API access to "api.kraken.com"
    When we get server time
    Then successful response is received
    And get server time response is validated OK

  @report
  Scenario: Get tradable asset pairs
    Given an API access to "api.kraken.com"
      | name     | altname |
      | XXBTZUSD | XBTUSD  |
      | XETHXXBT | ETHXBT  |

    When we get tradable asset pairs for "XXBTZUSD"
    Then successful response is received
    And get tradable asset pairs response is validated OK

  @report
  Scenario: Retrieve information about currently open orders
    Given an API access to "api.kraken.com"
    When we get open orders
    Then successful response is received
    And get open orders response is validated OK