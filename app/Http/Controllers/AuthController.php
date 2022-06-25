<?php

namespace App\Http\Controllers;

use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;

class AuthController extends Controller
{
    /**
     * @param RegisterRequest $request
     * @return string
     *
     * @OA\Post(
     *     path="/api/auth/register",
     *     operationId="auth.register",
     *     tags={"AuthController"},
     *     description="register new user",
     *     @OA\RequestBody(
     *          @OA\JsonContent(
     *              @OA\Property(
     *                  property="name",
     *                  type="string",
     *              ),
     *              @OA\Property(
     *                  property="email",
     *                  type="string",
     *              ),
     *              @OA\Property(
     *                  property="password",
     *                  type="string",
     *              ),
     *          )
     *     ),
     *     @OA\Response(
     *          response=200,
     *          description="user successfully registered, access token and user info returned",
     *          @OA\JsonContent(),
     *     ),
     * )
     */
    public function register(RegisterRequest $request)
    {
        $userData = $request->validated();
        $userData['password'] = bcrypt($userData['password']);
        /**
         * @var User $user
         */
        $user = User::query()->create($userData);
        $token = $user->createToken(User::API_TOKEN_NAME)->accessToken;
        return response()->json(
            [
                'access_token' => $token,
                'user' => $user,
            ]
        );
    }

    /**
     * @OA\Get(
     *     path="/api/auth/me",
     *     operationId="auth.me",
     *     tags={"AuthController"},
     *     description="get current user",
     *     security={{"bearer_token":{}}},
     *     @OA\Response(
     *          response=200,
     *          description="user is returned",
     *          @OA\JsonContent(),
     *     ),
     * )
     */
    public function me(): User
    {
        return auth()->user();
    }

    /**
     * @OA\Get(
     *     path="/api/auth/login",
     *     operationId="auth.login",
     *     tags={"AuthController"},
     *     description="get user token",
     *     @OA\Parameter(
     *          name="email",
     *          description="email",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string"
     *          )
     *      ),
     *     @OA\Parameter(
     *          name="password",
     *          description="password",
     *          required=true,
     *          in="query",
     *          @OA\Schema(
     *              type="string"
     *          )
     *      ),
     *     @OA\Response(
     *          response=200,
     *          description="user is returned",
     *          @OA\JsonContent(),
     *     ),
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $user = User::query()->firstWhere('email', $request->email);
        if (!password_verify($request->password, $user->password)) {
            return response()->json(
                ['error_message' => 'Incorrect Details. Please try again']);
        }

        $token = $user->createToken('API Token')->accessToken;
        return response()->json(
            [
                'access_token' => $token,
                'user' => $user,
            ]
        );
    }
}
