# Laravel Middleware Generator

🚀 **Generate Custom Middleware Automatically with Professional Code Structure**

A powerful Laravel package that automatically generates custom middleware with various authentication types, professional PHPDoc, and complete setup.

## ✨ Features

- ✅ **Multiple Middleware Types** (Role, Permission, Subscription, IP, Header, Custom)
- ✅ **Professional PHPDoc** with parameter documentation
- ✅ **Automatic Kernel Registration** in Laravel
- ✅ **Auth Configuration Updates** for role-based guards
- ✅ **Route Examples** with usage patterns
- ✅ **Test File Generation** with PHPUnit
- ✅ **Interactive Configuration** with beautiful console UI
- ✅ **Custom Error Messages** with smart defaults
- ✅ **Boolean Field Support** for role checks
- ✅ **Multi-Guard Support** (web, api, custom)

## 🚀 Installation

You can install the package via Composer:

```bash
composer require amranibrahem/laravel-middleware-generator
```
The package will automatically register its service provider.

## 📖 Usage

Basic Commands
Generate Role-Based Middleware
```bash
php artisan middleware:generate Admin
```
Generate with Specific Role

```bash
php artisan middleware:generate Admin --role=admin
```
Generate Permission-Based Middleware

```bash
php artisan middleware:generate CanEdit --type=permission --permission=edit-posts
```
Generate with API Guard

```bash
php artisan middleware:generate ApiAuth --guard=api
```
Generate with Tests

```bash
php artisan middleware:generate Admin --test
```
Advanced Examples
IP Whitelist Middleware

```bash
php artisan middleware:generate Internal --type=ip --ip="192.168.1.1,127.0.0.1"
```
Header-Based Authentication

```bash
php artisan middleware:generate ApiKey --type=header --header=X-API-Key --header-value=secret123
```
Subscription-Based Access

```bash
php artisan middleware:generate Premium --type=subscription --subscription=premium
```
Boolean Field Check

```bash
php artisan middleware:generate SuperAdmin --boolean --field=is_super_admin
```
Custom Error Message

```bash
php artisan middleware:generate Admin --message="Administrator access required" --code=401
```
## 🎯 Generated Code Examples
**Role-Based Middleware**
```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AdminMiddleware
{
    /**
     * Handle an incoming request.
     * 
     * @param  string  $role  Required role
     */
    public function handle(Request $request, Closure $next, string $role = 'admin'): Response
    {
        // Check if user has role = $role
        if ($request->user() && $request->user()->role === $role) {
            return $next($request);
        }

        return response()->json([
            'message' => 'Administrator access required',
            'code' => 403
        ], 403);
    }
}
```
**Permission-Based Middleware**
```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CanEditMiddleware
{
    /**
     * Handle an incoming request.
     * 
     * @param  string  $permission  Required permission
     */
    public function handle(Request $request, Closure $next, string $permission = 'edit-posts'): Response
    {
        // Check if user has permission: $permission
        if ($request->user() && $request->user()->can($permission)) {
            return $next($request);
        }

        return response()->json([
            'message' => 'Insufficient permissions',
            'code' => 403
        ], 403);
    }
}
```
**IP-Based Middleware**
```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class InternalMiddleware
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if request IP is in allowed list: 192.168.1.1,127.0.0.1
        if (in_array($request->ip(), ['192.168.1.1', '127.0.0.1'])) {
            return $next($request);
        }

        return response()->json([
            'message' => 'IP address not allowed',
            'code' => 403
        ], 403);
    }

    /**
     * Get allowed IP addresses
     */
    protected function getAllowedIps(): array
    {
        return ['192.168.1.1', '127.0.0.1'];
    }
}
```
## ⚙️ Command Options

| Option | Description | Default |
|:---|:---|:---|
| `--type` | Middleware type | `role` |
| `--role` | Role to check | name lowercase |
| `--permission` | Permission to check | `access.{name}` |
| `--subscription` | Subscription plan | `premium` |
| `--ip` | Allowed IPs | `127.0.0.1,192.168.1.1` |
| `--header` | Header to check | `X-API-Key` |
| `--header-value` | Header value | `your-secret-key` |
| `--message` | Error message | Type-based |
| `--code` | HTTP status | `403` |
| `--field` | User field | `role` |
| `--boolean` | Boolean field | `false` |
| `--model` | User model | `User` |
| `--guard` | Auth guard | `web` |
| `--test` | Generate test | `false` |


## 🛣️ Route Usage Examples

**Static Role Check**
```php
Route::middleware('admin')->group(function () {
Route::get('/admin/dashboard', [DashboardController::class, 'admin']);
});
```
**Dynamic Role Check**
```php
Route::middleware('admin:manager')->get('/manager', [ManagerController::class, 'index']);
````
**Permission-Based Routes**
```php
Route::middleware('canedit')->group(function () {
Route::post('/posts', [PostController::class, 'store']);
});

Route::middleware('canedit:delete-users')->delete('/users/{id}', [UserController::class, 'destroy']);
```
**IP-Based Routes**
```php
Route::middleware('internal')->group(function () {
Route::get('/internal/api', [InternalController::class, 'index']);
});
```
## 🧪 Generated Test Example
```php
<?php

namespace Tests\Unit\Middleware;

use Tests\TestCase;
use Illuminate\Http\Request;
use App\Http\Middleware\AdminMiddleware;
use Illuminate\Foundation\Testing\RefreshDatabase;

class AdminMiddlewareTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_allows_access_when_condition_met()
    {
        // TODO: Implement test based on your middleware logic
        $request = new Request();
        $middleware = new AdminMiddleware();
        
        $response = $middleware->handle($request, function ($req) {
            return response('OK');
        });

        $this->assertEquals('OK', $response->getContent());
    }

    /** @test */
    public function it_denies_access_when_condition_not_met()
    {
        // TODO: Implement test based on your middleware logic
        $request = new Request();
        $middleware = new AdminMiddleware();
        
        $response = $middleware->handle($request, function ($req) {
            return response('OK');
        });

        $this->assertEquals(403, $response->getStatusCode());
        $this->assertJsonStringEqualsJsonString(
            '{"message":"Administrator access required","code":403}',
            $response->getContent()
        );
    }
}
```
## 🎨 Console Output
```php
🚀 Starting Admin Middleware Generation...

🎯 Select Middleware Type:
───────────────────────
> Role-based (user.role === "admin")

📋 Generation Summary:
───────────────────────
🔹 Middleware Name: Admin
🔹 Type: role
🔹 Role Check: 'admin'
🔹 Status Code: 403
🔹 User Model: User
🔹 Guard: web
───────────────────────

📁 Creating Middleware File...
✅ Created middleware: AdminMiddleware.php

📝 Registering in Kernel...
✅ Registered middleware in Kernel.php ($middlewareAliases)

⚙️  Updating Auth Configuration...
✅ Added role guard to auth.php

🛣️  Creating Route Example...
✅ Added route example to api.php

🧪 Creating Test File...
✅ Created test: AdminMiddlewareTest.php

🎉 Middleware Generation Completed Successfully!
═══════════════════════════════════════
📋 Final Configuration:
   • Middleware: Admin
   • Type: role
   • Role: 'admin'
   • Field: 'role'
   • Boolean: No
   • Status Code: 403
   • Error Message: 'Administrator access required'
   • User Model: User
   • Guard: web
═══════════════════════════════════════
💡 Usage Examples:
Route::middleware('admin')->group(function () {
    Route::get('/admin/dashboard', [DashboardController::class, 'admin']);
});
═══════════════════════════════════════
🔧 Next Steps:
   1. Run: php artisan route:list
   2. Run: php artisan test
   3. Test your middleware thoroughly
═══════════════════════════════════════
```
## 🔧 Supported Middleware Types

### 1. **Role-Based**
- Checks user role against specified value
- Supports dynamic role parameters
- Boolean field support

### 2. **Permission-Based**
- Uses Laravel's authorization system
- Supports dynamic permission parameters
- Works with gates and policies

### 3. **Subscription-Based**
- Checks user subscription plans
- Perfect for SaaS applications
- Customizable field names

### 4. **IP-Based**
- IP address whitelisting
- Multiple IP support
- Internal API protection

### 5. **Header-Based**
- API key authentication
- Custom header validation
- Secret key verification

### 6. **Custom**
- Extensible template
- Manual implementation
- Custom business logic

## 🛡️ Security Features

- **Proper Authentication Checks** - Verifies user existence before role checks
- **HTTP Status Codes** - Appropriate status codes (401, 403, 503)
- **JSON Responses** - Consistent error response format
- **Input Validation** - Safe parameter handling
- **Guard Support** - Multiple authentication guards

## 🔄 Auto-Generated Files

1. **Middleware File** - `app/Http/Middleware/{Name}Middleware.php`
2. **Kernel Registration** - Auto-added to `app/Http/Kernel.php`
3. **Auth Configuration** - Updated `config/auth.php` for roles
4. **Route Examples** - Added to `routes/api.php` or `routes/web.php`
5. **Test Files** - Generated in `tests/Unit/Middleware/`

## 💡 Best Practices

### Use Boolean Fields for Single Roles
```bash
php artisan middleware:generate SuperAdmin --boolean --field=is_super_admin
```
**Custom HTTP Status Codes**
```bash
php artisan middleware:generate Auth --code=401 --message="Authentication required"
```
**API-Focused Middleware**
```bash
php artisan middleware:generate ApiAuth --guard=api --test
```
**Internal API Protection**
```bash
php artisan middleware:generate InternalApi --type=ip --ip="10.0.0.0/8" --log
```
## 🐛 Troubleshooting

### Middleware not found in routes?
- Run `php artisan route:list` to see registered middleware
- Check `Kernel.php` for proper registration

### Authentication not working?
- Verify guard configuration in `config/auth.php`
- Check user model field names match middleware configuration

### Tests failing?
- Implement actual test logic in generated test files
- Mock user authentication in tests

## 🚀 Comparison with Alternatives

| Feature | This Package | Manual Creation |
|---------|--------------|-----------------|
| Time Saving | ✅ (Seconds) | ❌ (Minutes/Hours) |
| Professional Structure | ✅ | ❌ |
| Auto Registration | ✅ | ❌ |
| Route Examples | ✅ | ❌ |
| Test Generation | ✅ | ❌ |
| Multiple Types | ✅ | ❌ |
| Interactive Setup | ✅ | ❌ |
| Error Handling | ✅ | ❌ |

## 📝 License

This package is open-sourced software licensed under the MIT license.

## 🤝 Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## 🐛 Reporting Issues

If you discover any issues, please use the [GitHub issue tracker](https://github.com/amranibrahem/laravel-middleware-generator/issues).

## 🏆 Credits

- [Amran iBrahem](https://github.com/amranibrahem)

## 🔗 Links

- [GitHub Repository](https://github.com/amranibrahem/laravel-middleware-generator)
- [Packagist](https://packagist.org/packages/amranibrahem/laravel-middleware-generator)
- [Issue Tracker](https://github.com/amranibrahem/laravel-middleware-generator/issues)

---

**⭐ Star us on GitHub if this package helped you!**

**🚀 Happy coding!**


