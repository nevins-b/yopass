var app = angular.module('yopass', ['ngRoute']);

app.controller('createController', function($scope, $http) {
  $scope.close = function(s) { $scope.full_url = undefined; }
  $scope.save = function(s) {
    if (s === undefined) {
      return;
    }
    if(s.expiration === undefined) {
      s.expiration = 3600;
    }

    var message = nacl.util.decodeUTF8(s.secret);
    var nonce = nacl.util.encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength));
    var decryption_key = nacl.util.encodeBase64(nacl.randomBytes(nacl.secretbox.keyLength));

    encrypted = nacl.util.encodeBase64(
      nacl.secretbox(
        message,
        nacl.util.decodeBase64(nonce),
        nacl.util.decodeBase64(decryption_key)
      )
    );

    $http.post('/secret', {secret: encrypted.toString(), nonce: nonce.toString(), expiration: parseInt(s.expiration)})
      .success(function(data, status, headers, config) {
        $scope.error = false; //clear errors on success
        $scope.secret = null; //clear secret on success
        base_url = window.location.protocol+"//"+window.location.host+"/#/s/";
        $scope.full_url = base_url+data.key+"/"+decryption_key;
        $scope.short_url = base_url+data.key;
        $scope.decryption_key = decryption_key;
        $scope.none = nonce;
      })
      .error(function(data, status, headers, config) {
        $scope.error = data.message
      });
  };
});

app.controller('ViewController', function($scope, $routeParams, $http) {
  function getSecret($key, $decryption_key) {
    $http.get('/secret/'+$routeParams.key)
      .success(function(data, status, headers, config) {
        $scope.display_form = false;
        var secret = nacl.secretbox.open(
          nacl.util.decodeBase64(data.secret),
          nacl.util.decodeBase64(data.nonce),
          nacl.util.decodeBase64($decryption_key)
        );
        if(secret == "" | !secret) {
          $scope.errorMessage = true;
          return;
        }
        $scope.secret = nacl.util.encodeUTF8(secret);
      })
      .error(function(data, status, headers, config) {
        $scope.errorMessage = true;
        $scope.display_form = false;
      });
  };

  if ($routeParams.decryption_key) {
    getSecret($routeParams.key, $routeParams.decryption_key);
  } else {
    $scope.display_form = true;
    $scope.view = function(form) {
      getSecret($routeParams.key, form.decryption_key);
    };
  };
});

app.config(function($routeProvider, $locationProvider) {
  $routeProvider
   .when('/s/:key/:decryption_key', {
    templateUrl: 'display-secret.html',
    controller: 'ViewController',
  })
  .when('/s/:key', {
    templateUrl: 'display-secret.html',
    controller: 'ViewController',
  })
  .when('/create', {
    templateUrl: 'create-secret.html',
    controller: 'createController'
  })
  .otherwise({
    redirectTo: '/create'
  });
});
