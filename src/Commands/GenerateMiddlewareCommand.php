<?php

namespace AmranIbrahem\MiddlewareGenerator\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Exception;

class GenerateMiddlewareCommand extends Command
{
    protected $signature = 'middleware:generate
                            {name : Middleware name (e.g., Admin, Manager, Teacher)}
                            {--role= : Role to check (e.g., admin, manager, user)}
                            {--message= : Custom error message}
                            {--code=403 : HTTP status code}
                            {--field=role : User field to check (e.g., role, type, level)}
                            {--boolean : Use boolean field (e.g., is_admin=true instead of role=admin)}';

    protected $description = 'Generate custom middleware with role-based authentication';

    public function handle()
    {
        $name = $this->argument('name');
        $role = $this->option('role') ?: strtolower($name);
        $code = (int)$this->option('code');
        $field = $this->option('field');
        $isBoolean = $this->option('boolean');

        $this->info("🚀 Starting {$name} Middleware Generation...");

        try {
            $this->showGenerationInfo($name, $role, $code, $field, $isBoolean);

            if (!$this->confirm('Do you want to continue with the generation?')) {
                $this->info('❌ Generation cancelled.');
                return 0;
            }

            $message = $this->getMessageChoice($role);

            $this->createMiddleware($name, $role, $message, $code, $field, $isBoolean);

            $this->updateKernel($name);

            $this->updateAuthConfig($role);

            $this->createRouteExample($name, $role);

            $this->showSuccessSummary($name, $role, $message, $code, $field, $isBoolean);

        } catch (Exception $e) {
            $this->error('❌ Error during middleware generation: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }

    protected function showGenerationInfo($name, $role, $code, $field, $isBoolean)
    {
        $this->info("\n📋 Generation Summary:");
        $this->line("───────────────────────");
        $this->info("🔹 Middleware Name: {$name}");

        if ($isBoolean) {
            $this->info("🔹 Field Check: '{$field}' = true");
            $this->info("🔹 Type: Boolean field");
        } else {
            $this->info("🔹 Role Check: '{$role}'");
            $this->info("🔹 Type: Role-based");
        }

        $this->info("🔹 Status Code: {$code}");
        $this->info("🔹 User Field: '{$field}'");
        $this->line("───────────────────────");
        $this->info("📁 Files that will be created/modified:");
        $this->line("   • app/Http/Middleware/{$name}.php");
        $this->line("   • app/Http/Kernel.php (registration)");
        $this->line("   • config/auth.php (guard configuration)");
        $this->line("   • routes/api.php (usage example)");
        $this->line("───────────────────────");
    }

    protected function getMessageChoice($role)
    {
        $customMessage = $this->option('message');
        if ($customMessage) {
            return $customMessage;
        }

        $defaultMessages = [
            'admin' => 'Administrator access required',
            'manager' => 'Manager access required',
            'user' => 'User access required',
            'teacher' => 'Teacher access required',
            'student' => 'Student access required',
            'moderator' => 'Moderator access required',
            'editor' => 'Editor access required',
            'superadmin' => 'Super Administrator access required',
            'customer' => 'Customer access required',
            'vendor' => 'Vendor access required'
        ];

        $defaultMessage = $defaultMessages[$role] ?? "Access denied. {$role} role required";

        $this->info("\n📝 Error Message Configuration:");
        $this->line("───────────────────────");
        $choices = [
            "Default: {$defaultMessage}",
            'Custom message',
            'Simple: Access denied',
            'Simple: Unauthorized access',
            'Simple: Insufficient permissions'
        ];

        $choice = $this->choice('Select message type:', $choices, 0);

        switch ($choice) {
            case $choices[0]: // Default
                return $defaultMessage;
            case $choices[1]: // Custom
                $this->info("💬 Enter your custom error message:");
                return $this->ask('Message:');
            case $choices[2]: // Simple: Access denied
                return 'Access denied';
            case $choices[3]: // Simple: Unauthorized access
                return 'Unauthorized access';
            case $choices[4]: // Simple: Insufficient permissions
                return 'Insufficient permissions';
            default:
                return $defaultMessage;
        }
    }

    protected function createMiddleware($name, $role, $message, $code, $field, $isBoolean = false)
    {
        $this->info("\n📁 Creating Middleware File...");

        $middlewarePath = app_path('Http/Middleware/' . $name . 'Middleware.php');
        $directory = dirname($middlewarePath);

        if (!File::exists($directory)) {
            File::makeDirectory($directory, 0755, true);
            $this->info("✅ Created directory: Http/Middleware/");
        }

        if (File::exists($middlewarePath)) {
            $overwrite = $this->confirm("⚠️  Middleware {$name} already exists. Overwrite?", true);
            if (!$overwrite) {
                throw new Exception('Middleware already exists and overwrite was cancelled.');
            }
        }

        $middlewareContent = $this->buildMiddlewareContent($name, $role, $message, $code, $field, $isBoolean);

        if (File::put($middlewarePath, $middlewareContent) === false) {
            throw new Exception("Failed to create middleware file: {$middlewarePath}");
        }

        $this->info("✅ Created middleware: {$name}.php");
    }

    protected function buildMiddlewareContent($name, $role, $message, $code, $field, $isBoolean = false)
    {
        if ($isBoolean) {
            $condition = "\$request->user() && \$request->user()->{$field} === true";
            $comment = "Check if user has {$field} = true";
        } else {
            $condition = "\$request->user() && \$request->user()->{$field} === '{$role}'";
            $comment = "Check if user has {$field} = '{$role}'";
        }

        return "<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class {$name}Middleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \\Closure(\\Illuminate\\Http\\Request): (\\Symfony\\Component\\HttpFoundation\\Response)  \$next
     */
    public function handle(Request \$request, Closure \$next): Response
    {
        // {$comment}
        if ({$condition}) {
            return \$next(\$request);
        }

        return response()->json([
            'message' => '{$message}'
        ], {$code});
    }
}";
    }

    protected function updateKernel($name)
    {
        $this->info("\n📝 Registering in Kernel...");

        $kernelPath = app_path('Http/Kernel.php');

        if (!File::exists($kernelPath)) {
            $this->warn("⚠️ Kernel.php not found, skipping kernel update...");
            return;
        }

        $content = File::get($kernelPath);
        $middlewareName = $this->getMiddlewareName($name);

        if (str_contains($content, "'{$middlewareName}' =>")) {
            $this->info("✅ Middleware already registered in Kernel.php");
            return;
        }

        $middlewareRegistered = false;

        if (preg_match('/(protected\s+\$middlewareAliases\s*=\s*\[)([^\]]*)(\];)/s', $content, $matches)) {
            $middlewareRegistered = true;
            $before = $matches[1];
            $middlewareList = $matches[2];
            $after = $matches[3];

            $newMiddlewareList = $middlewareList;
            if (!empty(trim($middlewareList))) {
                $newMiddlewareList .= "\n        ";
            }
            $newMiddlewareList .= "'{$middlewareName}' => \\App\\Http\\Middleware\\{$name}Middleware::class,";

            $newContent = str_replace($matches[0], $before . $newMiddlewareList . $after, $content);

            if (File::put($kernelPath, $newContent) !== false) {
                $this->info("✅ Registered middleware in Kernel.php (\$middlewareAliases)");
            } else {
                $this->warn("⚠️ Could not register middleware in Kernel.php");
            }
            return;
        }

        // المحاولة 2: البحث في $routeMiddleware (لإصدارات Laravel القديمة)
        if (preg_match('/(protected\s+\$routeMiddleware\s*=\s*\[)([^\]]*)(\];)/s', $content, $matches)) {
            $middlewareRegistered = true;
            $before = $matches[1];
            $middlewareList = $matches[2];
            $after = $matches[3];

            $newMiddlewareList = $middlewareList;
            if (!empty(trim($middlewareList))) {
                $newMiddlewareList .= "\n        ";
            }
            $newMiddlewareList .= "'{$middlewareName}' => \\App\\Http\\Middleware\\{$name}::class,";

            $newContent = str_replace($matches[0], $before . $newMiddlewareList . $after, $content);

            if (File::put($kernelPath, $newContent) !== false) {
                $this->info("✅ Registered middleware in Kernel.php (\$routeMiddleware)");
            } else {
                $this->warn("⚠️ Could not register middleware in Kernel.php");
            }
            return;
        }

        // المحاولة 3: البحث بدون protected
        if (preg_match('/(\$middlewareAliases\s*=\s*\[)([^\]]*)(\];)/s', $content, $matches)) {
            $middlewareRegistered = true;
            $before = $matches[1];
            $middlewareList = $matches[2];
            $after = $matches[3];

            $newMiddlewareList = $middlewareList;
            if (!empty(trim($middlewareList))) {
                $newMiddlewareList .= "\n        ";
            }
            $newMiddlewareList .= "'{$middlewareName}' => \\App\\Http\\Middleware\\{$name}::class,";

            $newContent = str_replace($matches[0], $before . $newMiddlewareList . $after, $content);

            if (File::put($kernelPath, $newContent) !== false) {
                $this->info("✅ Registered middleware in Kernel.php (\$middlewareAliases)");
            } else {
                $this->warn("⚠️ Could not register middleware in Kernel.php");
            }
            return;
        }

        // المحاولة 4: إذا لم يتم العثور على أي منهما، نضيف $middlewareAliases يدوياً
        $this->warn("⚠️ Could not find middlewareAliases or routeMiddleware array in Kernel.php, adding it manually...");

        if (preg_match('/(class\s+Kernel\s+extends\s+[^{]+\{[\s\S]*?)(protected\s+\$middleware\s*=)/', $content, $matches)) {
            $before = $matches[1];
            $after = $matches[2];

            $middlewareAliasesCode = "    protected \$middlewareAliases = [\n        '{$middlewareName}' => \\App\\Http\\Middleware\\{$name}::class,\n    ];\n\n    ";
            $newContent = str_replace($matches[0], $before . $middlewareAliasesCode . $after, $content);

            if (File::put($kernelPath, $newContent) !== false) {
                $this->info("✅ Created \$middlewareAliases and registered middleware in Kernel.php");
                $middlewareRegistered = true;
            }
        }

        if (!$middlewareRegistered) {
            $this->warn("⚠️ Could not find or create middleware arrays in Kernel.php");
            $this->warn("💡 Please manually register the middleware in app/Http/Kernel.php:");
            $this->line("'{$middlewareName}' => \\App\\Http\\Middleware\\{$name}::class,");
        }
    }

    protected function updateAuthConfig($role)
    {
        $this->info("\n⚙️  Updating Auth Configuration...");

        $authPath = config_path('auth.php');

        if (!File::exists($authPath)) {
            $this->warn("⚠️ auth.php not found, skipping auth config update...");
            return;
        }

        $content = File::get($authPath);

        // التحقق إذا كان الـ role موجود مسبقاً
        if (str_contains($content, "'{$role}' =>")) {
            $this->info("✅ Role already exists in auth.php");
            return;
        }

        $guardsUpdated = false;

        // المحاولة 1: البحث عن guards section
        if (preg_match('/(\'guards\'\s*=>\s*\[)([^\]]*?)(\],)/s', $content, $matches)) {
            $before = $matches[1];
            $guardsList = $matches[2];
            $after = $matches[3];

            // إضافة الـ guard الجديد
            $newGuardsList = $guardsList;
            if (!empty(trim($guardsList))) {
                $newGuardsList .= "\n        ";
            }
            $newGuardsList .= "'{$role}' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],";

            $newContent = str_replace($matches[0], $before . $newGuardsList . $after, $content);
            $guardsUpdated = true;
        }
        // المحاولة 2: إذا لم يتم العثور، نضيف قسم guards كاملاً
        else {
            $this->info("🔧 Adding guards section to auth.php...");

            // البحث عن return array
            if (preg_match('/(return\s+\[)([\s\S]*?)(\];\s*}$)/s', $content, $matches)) {
                $before = $matches[1];
                $configArray = $matches[2];
                $after = $matches[3];

                $guardsCode = "\n    'guards' => [\n        '{$role}' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],\n        'web' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],\n    ],";

                // إضافة guards قبل النهاية
                $newConfigArray = $configArray . $guardsCode;
                $newContent = str_replace($matches[0], $before . $newConfigArray . $after, $content);
                $guardsUpdated = true;
            }
        }

        if ($guardsUpdated && isset($newContent)) {
            if (File::put($authPath, $newContent) !== false) {
                $this->info("✅ Added role guard to auth.php");
            } else {
                $this->warn("⚠️ Could not update auth.php - permission issue");
            }
        } else {
            $this->warn("⚠️ Could not update auth.php configuration");
            $this->info("💡 You can manually add this to config/auth.php:");
            $this->line("'guards' => [");
            $this->line("    '{$role}' => [");
            $this->line("        'driver' => 'session',");
            $this->line("        'provider' => 'users',");
            $this->line("    ],");
            $this->line("],");
        }
    }

    protected function createRouteExample($name, $role)
    {
        $this->info("\n🛣️  Creating Route Example...");

        $routesPath = base_path('routes/api.php');
        $middlewareName = $this->getMiddlewareName($name);

        if (!File::exists($routesPath)) {
            $routesPath = base_path('routes/web.php');
            if (!File::exists($routesPath)) {
                $this->warn("⚠️ routes files not found, skipping route example...");
                return;
            }
        }

        $routeExample = "\n\n// {$name} Middleware Routes Example\nRoute::middleware('{$middlewareName}')->group(function () {\n    // Routes for {$role} role only\n    Route::get('/{$role}/dashboard', function () {\n        return response()->json(['message' => 'Welcome {$role}!']);\n    });\n});";

        if (File::append($routesPath, $routeExample) !== false) {
            $this->info("✅ Added route example to " . basename($routesPath));
        } else {
            $this->warn("⚠️ Could not add route example to " . basename($routesPath));
        }
    }

    protected function showSuccessSummary($name, $role, $message, $code, $field, $isBoolean = false)
    {
        $middlewareName = $this->getMiddlewareName($name);

        $this->info("\n🎉 Middleware Generation Completed Successfully!");
        $this->line("═══════════════════════════════════════");
        $this->info("📋 Final Configuration:");
        $this->line("   • Middleware: {$name}");

        if ($isBoolean) {
            $this->line("   • Field Check: '{$field}' = true");
            $this->line("   • Type: Boolean field");
        } else {
            $this->line("   • Role: '{$role}'");
            $this->line("   • Type: Role-based");
        }

        $this->line("   • Field: '{$field}'");
        $this->line("   • Status Code: {$code}");
        $this->line("   • Error Message: '{$message}'");
        $this->line("═══════════════════════════════════════");
        $this->info("💡 Usage Example:");
        $this->line("Route::middleware('{$middlewareName}')->group(function () {");
        $this->line("    Route::get('/admin/dashboard', [DashboardController::class, 'admin']);");
        $this->line("    Route::get('/admin/users', [UserController::class, 'index']);");
        $this->line("});");
        $this->line("═══════════════════════════════════════");
        $this->info("🔧 Next Steps:");
        $this->line("   1. Run: php artisan route:list");
        $this->line("   2. Test your middleware with different user roles");
        $this->line("   3. Add more routes protected by this middleware");
        $this->line("═══════════════════════════════════════\n");
    }

    protected function getMiddlewareName($name)
    {
        return strtolower($name);
    }
}
