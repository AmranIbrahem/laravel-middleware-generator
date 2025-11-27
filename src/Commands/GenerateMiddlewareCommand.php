<?php

namespace AmranIbrahem\MiddlewareGenerator\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Exception;

class GenerateMiddlewareCommand extends Command
{
    protected $signature = 'middleware:generate
        {name : Middleware name (e.g., Admin, Manager, Teacher)}
        {--type=role : Middleware type (role, permission, subscription, ip, header, custom)}
        {--role= : Role to check (e.g., admin, manager, user)}
        {--permission= : Permission to check (e.g., create-post, delete-user)}
        {--subscription= : Subscription plan (e.g., premium, pro, basic)}
        {--ip= : Allowed IP addresses (comma separated)}
        {--header= : Header to check (e.g., X-API-Key)}
        {--header-value= : Expected header value}
        {--message= : Custom error message}
        {--code=403 : HTTP status code}
        {--field=role : User field to check}
        {--boolean : Use boolean field}
        {--model=User : User model to use}
        {--guard=web : Authentication guard}
        {--test : Generate test file}';

    protected $description = 'Generate custom middleware with various authentication types';

    public function handle()
    {
        $name = $this->argument('name');

        $this->info("🚀 Starting {$name} Middleware Generation...");

        try {
            $type = $this->getMiddlewareType();
            $config = $this->configureByType($type, $name);

            $config['code'] = (int)$this->option('code');
            $config['field'] = $this->option('field');
            $config['boolean'] = $this->option('boolean');
            $config['model'] = $this->option('model');
            $config['guard'] = $this->option('guard');
            $config['message'] = $this->getMessageChoice($config);

            $this->showGenerationInfo($name, $config);

            if (!$this->confirm('Do you want to continue with the generation?')) {
                $this->info('❌ Generation cancelled.');
                return 0;
            }

            $this->createMiddleware($name, $config);

            $this->updateKernel($name);

            $this->updateAuthConfig($config);

            $this->createRouteExample($name, $config);

            if ($this->option('test')) {
                $this->createTest($name, $config);
            }

            $this->showSuccessSummary($name, $config);

        } catch (Exception $e) {
            $this->error('❌ Error during middleware generation: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }

    protected function getMiddlewareType()
    {
        $type = $this->option('type');

        if ($type && in_array($type, ['role', 'permission', 'subscription', 'ip', 'header', 'custom'])) {
            return $type;
        }

        $this->info("\n🎯 Select Middleware Type:");
        $this->line("───────────────────────");

        $types = [
            'role' => 'Role-based (user.role === "admin")',
            'permission' => 'Permission-based (user->can("create-post"))',
            'subscription' => 'Subscription-based (user.plan === "premium")',
            'ip' => 'IP Whitelist (allow specific IPs)',
            'header' => 'Header-based (check API key header)',
            'custom' => 'Custom Logic (manual implementation)'
        ];

        $choice = $this->choice('Middleware type:', $types, 'role');

        return array_search($choice, $types);
    }

    protected function configureByType($type, $name)
    {
        $config = ['type' => $type];

        switch ($type) {
            case 'role':
                $config['role'] = $this->option('role') ?: strtolower($name);
                $config['field'] = $this->option('field') ?: 'role';
                $config['boolean'] = $this->option('boolean');
                break;

            case 'permission':
                $config['permission'] = $this->option('permission') ?:
                    $this->ask('Permission name (e.g., create-post):', 'access.' . strtolower($name));
                break;

            case 'subscription':
                $config['subscription'] = $this->option('subscription') ?:
                    $this->choice('Subscription plan:', ['basic', 'pro', 'premium', 'enterprise'], 2);
                break;

            case 'ip':
                $config['ip'] = $this->option('ip') ?:
                    $this->ask('Allowed IPs (comma separated):', '127.0.0.1,192.168.1.1');
                break;

            case 'header':
                $config['header'] = $this->option('header') ?:
                    $this->ask('Header name:', 'X-API-Key');
                $config['header_value'] = $this->option('header-value') ?:
                    $this->ask('Expected header value:', 'your-secret-key');
                break;

            case 'custom':
                $config['custom'] = true;
                break;
        }

        return $config;
    }

    protected function showGenerationInfo($name, $config)
    {
        $this->info("\n📋 Generation Summary:");
        $this->line("───────────────────────");
        $this->info("🔹 Middleware Name: {$name}");
        $this->info("🔹 Type: {$config['type']}");

        switch ($config['type']) {
            case 'role':
                if ($config['boolean']) {
                    $this->info("🔹 Field Check: '{$config['field']}' = true");
                } else {
                    $this->info("🔹 Role Check: '{$config['role']}'");
                }
                break;
            case 'permission':
                $this->info("🔹 Permission: '{$config['permission']}'");
                break;
            case 'subscription':
                $this->info("🔹 Subscription: '{$config['subscription']}'");
                break;
            case 'ip':
                $this->info("🔹 Allowed IPs: {$config['ip']}");
                break;
            case 'header':
                $this->info("🔹 Header: '{$config['header']}' = '{$config['header_value']}'");
                break;
            case 'custom':
                $this->info("🔹 Logic: Custom implementation");
                break;
        }

        $this->info("🔹 Status Code: {$config['code']}");
        $this->info("🔹 User Model: {$config['model']}");
        $this->info("🔹 Guard: {$config['guard']}");
        $this->line("───────────────────────");
        $this->info("📁 Files that will be created/modified:");
        $this->line("   • app/Http/Middleware/{$name}Middleware.php");
        $this->line("   • app/Http/Kernel.php (registration)");
        $this->line("   • config/auth.php (guard configuration)");
        $this->line("   • routes/api.php (usage example)");

        if ($this->option('test')) {
            $this->line("   • tests/Unit/Middleware/{$name}MiddlewareTest.php");
        }

        $this->line("───────────────────────");
    }

    protected function getMessageChoice($config)
    {
        $customMessage = $this->option('message');
        if ($customMessage) {
            return $customMessage;
        }

        $defaultMessages = [
            'role' => [
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
            ],
            'permission' => 'Insufficient permissions',
            'subscription' => 'Subscription required',
            'ip' => 'IP address not allowed',
            'header' => 'Invalid API key',
            'custom' => 'Access denied'
        ];

        $defaultMessage = $defaultMessages[$config['type']] ?? "Access denied";

        if ($config['type'] === 'role' && isset($defaultMessages['role'][$config['role']])) {
            $defaultMessage = $defaultMessages['role'][$config['role']];
        }

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
            case $choices[0]:
                return $defaultMessage;
            case $choices[1]:
                $this->info("💬 Enter your custom error message:");
                return $this->ask('Message:');
            case $choices[2]:
                return 'Access denied';
            case $choices[3]:
                return 'Unauthorized access';
            case $choices[4]:
                return 'Insufficient permissions';
            default:
                return $defaultMessage;
        }
    }

    protected function createMiddleware($name, $config)
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

        $middlewareContent = $this->buildMiddlewareContent($name, $config);

        if (File::put($middlewarePath, $middlewareContent) === false) {
            throw new Exception("Failed to create middleware file: {$middlewarePath}");
        }

        $this->info("✅ Created middleware: {$name}Middleware.php");
    }

    protected function buildMiddlewareContent($name, $config)
    {
        $parameters = $this->buildParameters($config);
        $condition = $this->buildCondition($config);
        $comment = $this->buildComment($config);
        $customMethods = $this->buildCustomMethods($config);

        return "<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class {$name}Middleware
{
    /**
     * Handle an incoming request.{$parameters}
     */
    public function handle(Request \$request, Closure \$next{$this->buildParameterSignature($config)}): Response
    {
        // {$comment}
        if ({$condition}) {
            return \$next(\$request);
        }

        return response()->json([
            'message' => '{$config['message']}',
            'code' => {$config['code']}
        ], {$config['code']});
    }
{$customMethods}
}";
    }

    protected function buildParameters($config)
    {
        $params = [];

        if ($config['type'] === 'role' && !$config['boolean']) {
            $params[] = "\n     * @param  string  \$role  Required role";
        }

        if ($config['type'] === 'permission') {
            $params[] = "\n     * @param  string  \$permission  Required permission";
        }

        return implode('', $params);
    }

    protected function buildParameterSignature($config)
    {
        $params = [];

        if ($config['type'] === 'role' && !$config['boolean']) {
            $params[] = "string \$role = '{$config['role']}'";
        }

        if ($config['type'] === 'permission') {
            $params[] = "string \$permission = '{$config['permission']}'";
        }

        return $params ? ', ' . implode(', ', $params) : '';
    }

    protected function buildCondition($config)
    {
        switch ($config['type']) {
            case 'role':
                if ($config['boolean']) {
                    return "\$request->user() && \$request->user()->{$config['field']} === true";
                }
                return "\$request->user() && \$request->user()->{$config['field']} === \$role";

            case 'permission':
                return "\$request->user() && \$request->user()->can(\$permission)";

            case 'subscription':
                return "\$request->user() && \$request->user()->subscription_plan === '{$config['subscription']}'";

            case 'ip':
                $ips = explode(',', $config['ip']);
                $ips = array_map('trim', $ips);
                $ipsString = var_export($ips, true);
                return "in_array(\$request->ip(), {$ipsString})";

            case 'header':
                return "\$request->header('{$config['header']}') === '{$config['header_value']}'";

            case 'custom':
                return "\$request->user() && \$this->customCheck(\$request->user())";

            default:
                return "false";
        }
    }

    protected function buildComment($config)
    {
        switch ($config['type']) {
            case 'role':
                return $config['boolean'] ?
                    "Check if user has {$config['field']} = true" :
                    "Check if user has {$config['field']} = \$role";

            case 'permission':
                return "Check if user has permission: \$permission";

            case 'subscription':
                return "Check if user has subscription: {$config['subscription']}";

            case 'ip':
                return "Check if request IP is in allowed list: {$config['ip']}";

            case 'header':
                return "Check if header {$config['header']} matches expected value";

            case 'custom':
                return "Custom middleware logic";

            default:
                return "Middleware access check";
        }
    }

    protected function buildCustomMethods($config)
    {
        $methods = '';

        if ($config['type'] === 'custom') {
            $methods = "

    /**
     * Custom validation logic
     */
    protected function customCheck(\$user): bool
    {
        // Add your custom validation logic here
        return true;
    }";
        }

        if ($config['type'] === 'ip') {
            $methods = "

    /**
     * Get allowed IP addresses
     */
    protected function getAllowedIps(): array
    {
        return [" . implode(', ', array_map(function($ip) {
                    return "'$ip'";
                }, explode(',', $config['ip']))) . "];
    }";
        }

        return $methods;
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

        if (preg_match('/(protected\s+\$routeMiddleware\s*=\s*\[)([^\]]*)(\];)/s', $content, $matches)) {
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
                $this->info("✅ Registered middleware in Kernel.php (\$routeMiddleware)");
            } else {
                $this->warn("⚠️ Could not register middleware in Kernel.php");
            }
            return;
        }

        if (preg_match('/(\$middlewareAliases\s*=\s*\[)([^\]]*)(\];)/s', $content, $matches)) {
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

        $this->warn("⚠️ Could not find middlewareAliases or routeMiddleware array in Kernel.php, adding it manually...");

        if (preg_match('/(class\s+Kernel\s+extends\s+[^{]+\{[\s\S]*?)(protected\s+\$middleware\s*=)/', $content, $matches)) {
            $before = $matches[1];
            $after = $matches[2];

            $middlewareAliasesCode = "    protected \$middlewareAliases = [\n        '{$middlewareName}' => \\App\\Http\\Middleware\\{$name}Middleware::class,\n    ];\n\n    ";
            $newContent = str_replace($matches[0], $before . $middlewareAliasesCode . $after, $content);

            if (File::put($kernelPath, $newContent) !== false) {
                $this->info("✅ Created \$middlewareAliases and registered middleware in Kernel.php");
                $middlewareRegistered = true;
            }
        }

        if (!$middlewareRegistered) {
            $this->warn("⚠️ Could not find or create middleware arrays in Kernel.php");
            $this->warn("💡 Please manually register the middleware in app/Http/Kernel.php:");
            $this->line("'{$middlewareName}' => \\App\\Http\\Middleware\\{$name}Middleware::class,");
        }
    }

    protected function updateAuthConfig($config)
    {
        if ($config['type'] !== 'role') {
            return;
        }

        $this->info("\n⚙️  Updating Auth Configuration...");

        $authPath = config_path('auth.php');

        if (!File::exists($authPath)) {
            $this->warn("⚠️ auth.php not found, skipping auth config update...");
            return;
        }

        $content = File::get($authPath);

        if (str_contains($content, "'{$config['role']}' =>")) {
            $this->info("✅ Role already exists in auth.php");
            return;
        }

        $guardsUpdated = false;

        if (preg_match('/(\'guards\'\s*=>\s*\[)([^\]]*?)(\],)/s', $content, $matches)) {
            $before = $matches[1];
            $guardsList = $matches[2];
            $after = $matches[3];

            $newGuardsList = $guardsList;
            if (!empty(trim($guardsList))) {
                $newGuardsList .= "\n        ";
            }
            $newGuardsList .= "'{$config['role']}' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],";

            $newContent = str_replace($matches[0], $before . $newGuardsList . $after, $content);
            $guardsUpdated = true;
        }
        else {
            $this->info("🔧 Adding guards section to auth.php...");

            if (preg_match('/(return\s+\[)([\s\S]*?)(\];\s*}$)/s', $content, $matches)) {
                $before = $matches[1];
                $configArray = $matches[2];
                $after = $matches[3];

                $guardsCode = "\n    'guards' => [\n        '{$config['role']}' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],\n        'web' => [\n            'driver' => 'session',\n            'provider' => 'users',\n        ],\n    ],";

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
            $this->line("    '{$config['role']}' => [");
            $this->line("        'driver' => 'session',");
            $this->line("        'provider' => 'users',");
            $this->line("    ],");
            $this->line("],");
        }
    }

    protected function createRouteExample($name, $config)
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

        $routeExample = $this->buildRouteExample($name, $config, $middlewareName);

        if (File::append($routesPath, $routeExample) !== false) {
            $this->info("✅ Added route example to " . basename($routesPath));
        } else {
            $this->warn("⚠️ Could not add route example to " . basename($routesPath));
        }
    }

    protected function buildRouteExample($name, $config, $middlewareName)
    {
        $example = "\n\n// {$name} Middleware Routes Example";

        switch ($config['type']) {
            case 'role':
                if ($config['boolean']) {
                    $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                    $example .= "\n    // Routes for users with {$config['field']} = true";
                    $example .= "\n    Route::get('/admin/dashboard', function () {";
                    $example .= "\n        return response()->json(['message' => 'Welcome admin!']);";
                    $example .= "\n    });";
                    $example .= "\n});";
                } else {
                    $example .= "\n// Static role check";
                    $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                    $example .= "\n    Route::get('/{$config['role']}/dashboard', function () {";
                    $example .= "\n        return response()->json(['message' => 'Welcome {$config['role']}!']);";
                    $example .= "\n    });";
                    $example .= "\n});";

                    $example .= "\n\n// Dynamic role check";
                    $example .= "\nRoute::middleware('{$middlewareName}:manager')->get('/manager', function () {";
                    $example .= "\n    return response()->json(['message' => 'Welcome manager!']);";
                    $example .= "\n});";
                }
                break;

            case 'permission':
                $example .= "\n// Static permission check";
                $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                $example .= "\n    Route::post('/posts', function () {";
                $example .= "\n        return response()->json(['message' => 'Post created!']);";
                $example .= "\n    });";
                $example .= "\n});";

                $example .= "\n\n// Dynamic permission check";
                $example .= "\nRoute::middleware('{$middlewareName}:delete-users')->delete('/users/{id}', function () {";
                $example .= "\n    return response()->json(['message' => 'User deleted!']);";
                $example .= "\n});";
                break;

            case 'subscription':
                $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                $example .= "\n    Route::get('/premium/content', function () {";
                $example .= "\n        return response()->json(['message' => 'Premium content accessed!']);";
                $example .= "\n    });";
                $example .= "\n});";
                break;

            case 'ip':
                $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                $example .= "\n    Route::get('/internal/api', function () {";
                $example .= "\n        return response()->json(['message' => 'Internal API accessed!']);";
                $example .= "\n    });";
                $example .= "\n});";
                break;

            case 'header':
                $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                $example .= "\n    Route::get('/secure/endpoint', function () {";
                $example .= "\n        return response()->json(['message' => 'Secure endpoint accessed!']);";
                $example .= "\n    });";
                $example .= "\n});";
                break;

            case 'custom':
                $example .= "\nRoute::middleware('{$middlewareName}')->group(function () {";
                $example .= "\n    Route::get('/custom/protected', function () {";
                $example .= "\n        return response()->json(['message' => 'Custom protected route!']);";
                $example .= "\n    });";
                $example .= "\n});";
                break;
        }

        return $example;
    }

    protected function createTest($name, $config)
    {
        $this->info("\n🧪 Creating Test File...");

        $testPath = base_path("tests/Unit/Middleware/{$name}MiddlewareTest.php");
        $directory = dirname($testPath);

        if (!File::exists($directory)) {
            File::makeDirectory($directory, 0755, true);
        }

        $testContent = $this->buildTestContent($name, $config);

        if (File::put($testPath, $testContent) !== false) {
            $this->info("✅ Created test: {$name}MiddlewareTest.php");
        } else {
            $this->warn("⚠️ Could not create test file");
        }
    }

    protected function buildTestContent($name, $config)
    {
        return "<?php

namespace Tests\Unit\Middleware;

use Tests\TestCase;
use Illuminate\Http\Request;
use App\Http\Middleware\\{$name}Middleware;
use Illuminate\Foundation\Testing\RefreshDatabase;

class {$name}MiddlewareTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_allows_access_when_condition_met()
    {
        // TODO: Implement test based on your middleware logic
        \$request = new Request();
        \$middleware = new {$name}Middleware();

        \$response = \$middleware->handle(\$request, function (\$req) {
            return response('OK');
        });

        \$this->assertEquals('OK', \$response->getContent());
    }

    /** @test */
    public function it_denies_access_when_condition_not_met()
    {
        // TODO: Implement test based on your middleware logic
        \$request = new Request();
        \$middleware = new {$name}Middleware();

        \$response = \$middleware->handle(\$request, function (\$req) {
            return response('OK');
        });

        \$this->assertEquals({$config['code']}, \$response->getStatusCode());
        \$this->assertJsonStringEqualsJsonString(
            '{\"message\":\"{$config['message']}\",\"code\":{$config['code']}}',
            \$response->getContent()
        );
    }
}";
    }

    protected function showSuccessSummary($name, $config)
    {
        $middlewareName = $this->getMiddlewareName($name);

        $this->info("\n🎉 Middleware Generation Completed Successfully!");
        $this->line("═══════════════════════════════════════");
        $this->info("📋 Final Configuration:");
        $this->line("   • Middleware: {$name}");
        $this->line("   • Type: {$config['type']}");

        switch ($config['type']) {
            case 'role':
                $this->line("   • Role: '{$config['role']}'");
                $this->line("   • Field: '{$config['field']}'");
                $this->line("   • Boolean: " . ($config['boolean'] ? 'Yes' : 'No'));
                break;
            case 'permission':
                $this->line("   • Permission: '{$config['permission']}'");
                break;
            case 'subscription':
                $this->line("   • Subscription: '{$config['subscription']}'");
                break;
            case 'ip':
                $this->line("   • Allowed IPs: {$config['ip']}");
                break;
            case 'header':
                $this->line("   • Header: '{$config['header']}'");
                $this->line("   • Expected Value: '{$config['header_value']}'");
                break;
        }

        $this->line("   • Status Code: {$config['code']}");
        $this->line("   • Error Message: '{$config['message']}'");
        $this->line("   • User Model: {$config['model']}");
        $this->line("   • Guard: {$config['guard']}");
        $this->line("═══════════════════════════════════════");

        $this->showUsageExamples($name, $config, $middlewareName);
    }

    protected function showUsageExamples($name, $config, $middlewareName)
    {
        $this->info("💡 Usage Examples:");

        switch ($config['type']) {
            case 'role':
                if ($config['boolean']) {
                    $this->line("Route::middleware('{$middlewareName}')->group(function () {");
                    $this->line("    Route::get('/admin/dashboard', [DashboardController::class, 'admin']);");
                    $this->line("});");
                } else {
                    $this->line("// Static role");
                    $this->line("Route::middleware('{$middlewareName}')->group(function () {");
                    $this->line("    Route::get('/admin/dashboard', [DashboardController::class, 'admin']);");
                    $this->line("});");

                    $this->line("// Dynamic role");
                    $this->line("Route::middleware('{$middlewareName}:manager')->get('/manager', [ManagerController::class, 'index']);");
                }
                break;

            case 'permission':
                $this->line("// Static permission");
                $this->line("Route::middleware('{$middlewareName}')->group(function () {");
                $this->line("    Route::post('/posts', [PostController::class, 'store']);");
                $this->line("});");

                $this->line("// Dynamic permission");
                $this->line("Route::middleware('{$middlewareName}:delete-users')->delete('/users/{id}', [UserController::class, 'destroy']);");
                break;
        }

        $this->line("═══════════════════════════════════════");
        $this->info("🔧 Next Steps:");
        $this->line("   1. Run: php artisan route:list");
        if ($this->option('test')) {
            $this->line("   2. Run: php artisan test");
        }
        $this->line("   3. Test your middleware thoroughly");
        $this->line("═══════════════════════════════════════\n");
    }

    protected function getMiddlewareName($name)
    {
        return strtolower($name);
    }
}
