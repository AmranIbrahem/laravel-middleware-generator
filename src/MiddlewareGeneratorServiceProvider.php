<?php

namespace AmranIbrahem\MiddlewareGenerator;

use Illuminate\Support\ServiceProvider;
use AmranIbrahem\MiddlewareGenerator\Commands\GenerateMiddlewareCommand;

class MiddlewareGeneratorServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->commands([
            GenerateMiddlewareCommand::class,
        ]);
    }

    public function boot()
    {

    }
}
