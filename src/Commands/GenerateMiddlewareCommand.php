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
                            {--field=role : User field to check (e.g., role, type, level)}';

    protected $description = 'Generate custom middleware with role-based authentication';

    public function handle()
    {
        $name = $this->argument('name');
        $role = $this->option('role') ?: strtolower($name);
        $message = $this->option('message') ?: $this->getDefaultMessage($role);
        $code = (int)$this->option('code');
        $field = $this->option('field');

        $this->info("🚀 Generating {$name} middleware...");

        try {
            // 1. إنشاء الميدلوير
            $this->createMiddleware($name, $role, $message, $code, $field);

            // 2. تحديث Kernel.php
            $this->updateKernel($name);

            // 3. تحديث auth.php
            $this->updateAuthConfig($role);

            // 4. إنشاء مثال للـ routes
            $this->createRouteExample($name, $role);

            $this->info("✅ Middleware {$name} generated successfully!");
            $this->info("👤 Role: {$role}");
            $this->info("📝 Message: {$message}");
            $this->info("🔢 Status Code: {$code}");
            $this->info("🏷️ Field: {$field}");
            $this->info("\n💡 Usage example:");
            $this->info("Route::middleware('{$this->getMiddlewareName($name)}')->group(function () {");
            $this->info("    // Your protected routes here");
            $this->info("});");

        } catch (Exception $e) {
            $this->error('❌ Error during middleware generation: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }

    protected function createMiddleware($name, $role, $message, $code, $field)
    {
        $middlewarePath = app_path('Http/Middleware/' . $name . '.php');
        $directory = dirname($middlewarePath);

        if (!File::exists($directory)) {
            File::makeDirectory($directory, 0755, true);
        }

        if (File::exists($middlewarePath)) {
            $overwrite = $this->confirm("Middleware {$name} already exists. Overwrite?");
            if (!$overwrite) {
                throw new Exception('Middleware already exists and overwrite was cancelled.');
            }
        }

        $middlewareContent = $this->buildMiddlewareContent($name, $role, $message, $code, $field);

        if (File::put($middlewarePath, $middlewareContent) === false) {
            throw new Exception("Failed to create middleware file: {$middlewarePath}");
        }

        $this->info("✅ Created middleware: {$name}");
    }

    protected function buildMiddlewareContent($name, $role, $message, $code, $field)
    {
        $messageJson = json_encode(['message' => $message]);

        return "<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class {$name}
{
    /**
     * Handle an incoming request.
     *
     * @param  \\Closure(\\Illuminate\\Http\\Request): (\\Symfony\\Component\\HttpFoundation\\Response)  \$next
     */
    public function handle(Request \$request, Closure \$next): Response
    {
        if (\$request->user() && \$request->user()->{$field} === '{$role}') {
            return \$next(\$request);
        }

        return response()->json({$messageJson}, {$code});
    }
}";
    }

    protected function updateKernel($name)
    {
        $kernelPath = app_path('Http/Kernel.php');

        if (!File::exists($kernelPath)) {
            $this->warn("⚠️ Kernel.php not found, skipping kernel update...");
            return;
        }

        $content = File::get($kernelPath);
        $middlewareName = $this->getMiddlewareName($name);

        // التحقق إذا كان الميدلوير مسجل مسبقاً
        if (str_contains($content, "'{$middlewareName}' =>")) {
            $this->info("✅ Middleware already registered in Kernel.php");
            return;
        }

        // البحث عن مكان إضافة الميدلوير
        if (str_contains($content, "protected \$routeMiddleware = [")) {
            $search = "protected \$routeMiddleware = [";
            $replace = "protected \$routeMiddleware = [\n        '{$middlewareName}' => \\App\\Http\\Middleware\\{$name}::class,";

            $content = str_replace($search, $replace, $content);

            if (File::put($kernelPath, $content) !== false) {
                $this->info("✅ Registered middleware in Kernel.php");
            } else {
                $this->warn("⚠️ Could not register middleware in Kernel.php");
            }
        } else {
            $this->warn("⚠️ Could not find routeMiddleware in Kernel.php");
        }
    }

    protected function updateAuthConfig($role)
    {
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

        // البحث عن مكان إضافة الـ roles
        if (str_contains($content, "'guards' => [")) {
            $search = "'guards' => [";
            $replace = "'guards' => [\n        '{$role}' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],";

            $content = str_replace($search, $replace, $content);

            if (File::put($authPath, $content) !== false) {
                $this->info("✅ Added role guard to auth.php");
            } else {
                $this->warn("⚠️ Could not update auth.php");
            }
        } else {
            $this->warn("⚠️ Could not find guards section in auth.php");
        }
    }

    protected function createRouteExample($name, $role)
    {
        $routesPath = base_path('routes/api.php');
        $middlewareName = $this->getMiddlewareName($name);

        if (!File::exists($routesPath)) {
            $this->warn("⚠️ routes/api.php not found, skipping route example...");
            return;
        }

        $routeExample = "\n\n// {$name} Middleware Routes Example\nRoute::middleware('{$middlewareName}')->group(function () {\n    // Routes for {$role} role only\n    Route::get('/{$role}/dashboard', function () {\n        return response()->json(['message' => 'Welcome {$role}!']);\n    });\n});";

        if (File::append($routesPath, $routeExample) !== false) {
            $this->info("✅ Added route example to routes/api.php");
        } else {
            $this->warn("⚠️ Could not add route example to routes/api.php");
        }
    }

    protected function getDefaultMessage($role)
    {
        $messages = [
            'admin' => 'Administrator access required',
            'manager' => 'Manager access required',
            'user' => 'User access required',
            'teacher' => 'Teacher access required',
            'student' => 'Student access required',
            'moderator' => 'Moderator access required',
            'editor' => 'Editor access required'
        ];

        return $messages[$role] ?? "Access denied. {$role} role required";
    }

    protected function getMiddlewareName($name)
    {
        return strtolower($name);
    }
}
