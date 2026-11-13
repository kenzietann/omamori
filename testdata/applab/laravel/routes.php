<?php
// A small Laravel API. Failed logins are written with Log::warning and a context, as Laravel apps usually do.
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

Route::post('/auth/login', function (Request $request) {
    if ($request->input('username') === 'alice' && $request->input('password') === 'Summer2026!') {
        return response()->json(['token' => 't']);
    }
    Log::warning('Failed login', ['email' => $request->input('username'), 'ip' => $request->ip()]);
    return response()->json(['error' => 'invalid credentials'], 401);
});
Route::get('/api/items', function (Request $request) {
    $id = (string) $request->query('id', '');
    if (str_contains($id, "'")) {
        Log::error("SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax near '{$id}'");
        return response()->json(['error' => 'server error'], 500);
    }
    return response()->json([]);
});
