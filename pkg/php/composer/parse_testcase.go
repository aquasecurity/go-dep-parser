package composer

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerNormal = []types.Library{
		types.NewLibrary("pear/log", "1.13.1", ""),
		types.NewLibrary("pear/pear_exception", "v1.0.0", ""),
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerLaravel = []types.Library{
		types.NewLibrary("guzzlehttp/guzzle", "6.3.3", ""),
		types.NewLibrary("guzzlehttp/promises", "v1.3.1", ""),
		types.NewLibrary("guzzlehttp/psr7", "1.5.2", ""),
		types.NewLibrary("laravel/installer", "v2.0.1", ""),
		types.NewLibrary("pear/log", "1.13.1", ""),
		types.NewLibrary("pear/pear_exception", "v1.0.0", ""),
		types.NewLibrary("psr/http-message", "1.0.1", ""),
		types.NewLibrary("ralouphie/getallheaders", "2.0.5", ""),
		types.NewLibrary("symfony/console", "v4.2.7", ""),
		types.NewLibrary("symfony/contracts", "v1.0.2", ""),
		types.NewLibrary("symfony/filesystem", "v4.2.7", ""),
		types.NewLibrary("symfony/polyfill-ctype", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-mbstring", "v1.11.0", ""),
		types.NewLibrary("symfony/process", "v4.2.7", ""),
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerSymfony = []types.Library{
		types.NewLibrary("doctrine/annotations", "v1.6.1", ""),
		types.NewLibrary("doctrine/cache", "v1.8.0", ""),
		types.NewLibrary("doctrine/collections", "v1.6.1", ""),
		types.NewLibrary("doctrine/event-manager", "v1.0.0", ""),
		types.NewLibrary("doctrine/lexer", "v1.0.1", ""),
		types.NewLibrary("doctrine/persistence", "1.1.1", ""),
		types.NewLibrary("doctrine/reflection", "v1.0.0", ""),
		types.NewLibrary("fig/link-util", "1.0.0", ""),
		types.NewLibrary("guzzlehttp/guzzle", "6.3.3", ""),
		types.NewLibrary("guzzlehttp/promises", "v1.3.1", ""),
		types.NewLibrary("guzzlehttp/psr7", "1.5.2", ""),
		types.NewLibrary("laravel/installer", "v2.0.1", ""),
		types.NewLibrary("pear/log", "1.13.1", ""),
		types.NewLibrary("pear/pear_exception", "v1.0.0", ""),
		types.NewLibrary("psr/cache", "1.0.1", ""),
		types.NewLibrary("psr/container", "1.0.0", ""),
		types.NewLibrary("psr/http-message", "1.0.1", ""),
		types.NewLibrary("psr/link", "1.0.0", ""),
		types.NewLibrary("psr/log", "1.1.0", ""),
		types.NewLibrary("psr/simple-cache", "1.0.1", ""),
		types.NewLibrary("ralouphie/getallheaders", "2.0.5", ""),
		types.NewLibrary("symfony/contracts", "v1.0.2", ""),
		types.NewLibrary("symfony/polyfill-ctype", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-intl-icu", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-mbstring", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-php72", "v1.11.0", ""),
		types.NewLibrary("symfony/symfony", "v4.2.7", ""),
		types.NewLibrary("twig/twig", "v2.9.0", ""),
	}

	// docker run --name composer --rm -it composer:1.8 bash
	// composer require pear/log
	// composer require "laravel/installer"
	// composer require "symfony/symfony"
	// composer require fzaninotto/faker --dev
	// composer show -i -f json | jq -rc '.installed[] | "{\"\(.name)\", \"\(.version)\", ""},"'
	ComposerWithDev = []types.Library{
		types.NewLibrary("doctrine/annotations", "v1.6.1", ""),
		types.NewLibrary("doctrine/cache", "v1.8.0", ""),
		types.NewLibrary("doctrine/collections", "v1.6.1", ""),
		types.NewLibrary("doctrine/event-manager", "v1.0.0", ""),
		types.NewLibrary("doctrine/lexer", "v1.0.1", ""),
		types.NewLibrary("doctrine/persistence", "1.1.1", ""),
		types.NewLibrary("doctrine/reflection", "v1.0.0", ""),
		types.NewLibrary("fig/link-util", "1.0.0", ""),
		types.NewLibrary("guzzlehttp/guzzle", "6.3.3", ""),
		types.NewLibrary("guzzlehttp/promises", "v1.3.1", ""),
		types.NewLibrary("guzzlehttp/psr7", "1.5.2", ""),
		types.NewLibrary("laravel/installer", "v2.0.1", ""),
		types.NewLibrary("pear/log", "1.13.1", ""),
		types.NewLibrary("pear/pear_exception", "v1.0.0", ""),
		types.NewLibrary("psr/cache", "1.0.1", ""),
		types.NewLibrary("psr/container", "1.0.0", ""),
		types.NewLibrary("psr/http-message", "1.0.1", ""),
		types.NewLibrary("psr/link", "1.0.0", ""),
		types.NewLibrary("psr/log", "1.1.0", ""),
		types.NewLibrary("psr/simple-cache", "1.0.1", ""),
		types.NewLibrary("ralouphie/getallheaders", "2.0.5", ""),
		types.NewLibrary("symfony/contracts", "v1.0.2", ""),
		types.NewLibrary("symfony/polyfill-ctype", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-intl-icu", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-mbstring", "v1.11.0", ""),
		types.NewLibrary("symfony/polyfill-php72", "v1.11.0", ""),
		types.NewLibrary("symfony/symfony", "v4.2.7", ""),
		types.NewLibrary("twig/twig", "v2.9.0", ""),
	}
)
