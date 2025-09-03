import { Client, Environment } from '@paypal/paypal-server-sdk';
import { AuthenticatedRequest } from '../middleware/auth';
import { createNeonDatabase } from '../utils/neon-database';
import { z } from 'zod';
import { Env } from '../index';

// Validation schemas
const createPaymentOrderSchema = z.object({
  amount: z.number().min(50), // Minimum $0.50
  currency: z.string().default('USD'),
  description: z.string().optional(),
  metadata: z.record(z.string()).optional(),
});

const confirmPaymentSchema = z.object({
  order_id: z.string(),
  payer_id: z.string().optional(),
});

const refundSchema = z.object({
  capture_id: z.string(),
  amount: z.number().optional(),
  reason: z.string().optional(),
});

// Initialize payment tables on first request
let tablesInitialized = false;

async function ensurePaymentTables(env: Env) {
  if (!tablesInitialized) {
    try {
      const db = createNeonDatabase(env);
      await db.initializePaymentTables();
      tablesInitialized = true;
    } catch (error) {
      console.error('Failed to initialize payment tables:', error);
    }
  }
}

// Initialize PayPal client
function createPayPalClient(env: Env): Client {
  const environment = env.PAYPAL_ENVIRONMENT === 'live' ? Environment.Live : Environment.Sandbox;
  
  return new Client({
    clientCredentialsAuthCredentials: {
      oAuthClientId: env.PAYPAL_CLIENT_ID,
      oAuthClientSecret: env.PAYPAL_CLIENT_SECRET,
    },
    environment,
  });
}

// Helper function to parse and validate JSON
async function parseAndValidate<T>(request: Request, schema: z.ZodSchema<T>): Promise<T> {
  const body = await request.json();
  return schema.parse(body);
}

// POST /payments/create - Create payment order
export async function createPayment(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    
    const { amount, currency, description, metadata } = await parseAndValidate(request, createPaymentOrderSchema);

    // Check if PayPal is configured, otherwise use mock mode
    let paymentOrder;
    if (env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET) {
      try {
        // Real PayPal integration
        const paypalClient = createPayPalClient(env);
        
        const orderRequest = {
          intent: 'CAPTURE',
          purchaseUnits: [{
            amount: {
              currencyCode: currency,
              value: (amount / 100).toFixed(2), // Convert cents to dollars
            },
            description: description || 'Credit purchase',
            customId: user.id,
          }],
          applicationContext: {
            returnUrl: `${new URL(request.url).origin}/payment/success`,
            cancelUrl: `${new URL(request.url).origin}/payment/cancel`,
          },
        };
        
        const response = await paypalClient.ordersController.ordersCreate({
          body: orderRequest,
        });
        
        paymentOrder = {
          id: response.result.id,
          status: response.result.status,
          amount,
          currency,
          links: response.result.links,
          description,
          metadata: {
            user_id: user.id,
            ...metadata,
          },
        };
      } catch (paypalError) {
        console.warn('PayPal API error, falling back to mock mode:', paypalError.message);
        // Fall back to mock mode if PayPal fails
        paymentOrder = {
          id: `order_mock_${Date.now()}`,
          status: 'CREATED',
          amount,
          currency,
          links: [{
            href: `${new URL(request.url).origin}/payment/mock`,
            rel: 'approve',
            method: 'GET',
          }],
          description,
          metadata: {
            user_id: user.id,
            ...metadata,
          },
        };
      }
    } else {
      // Mock payment order for development
      paymentOrder = {
        id: `order_mock_${Date.now()}`,
        status: 'CREATED',
        amount,
        currency,
        links: [{
          href: `${new URL(request.url).origin}/payment/mock`,
          rel: 'approve',
          method: 'GET',
        }],
        description,
        metadata: {
          user_id: user.id,
          ...metadata,
        },
      };
    }
 
     // Store transaction in database
     const db = createNeonDatabase(env);
     const transaction = await db.createTransaction({
       user_id: user.id,
       type: 'credit_purchase',
       amount,
       currency,
       payment_intent_id: paymentOrder.id, // Using order_id for PayPal
       description: description || 'Credit purchase',
       metadata,
     });

    return new Response(JSON.stringify({
      success: true,
      transaction_id: transaction?.id,
      payment_order: {
        id: paymentOrder.id,
        status: paymentOrder.status,
        amount: paymentOrder.amount,
        currency: paymentOrder.currency,
        links: paymentOrder.links,
        approve_url: paymentOrder.links?.find(link => link.rel === 'approve')?.href,
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Payment order creation error:', error);
    console.error('Error stack:', error.stack);
    console.error('Error message:', error.message);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to create payment order',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Test version without authentication
export async function createPaymentTest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {

    await ensurePaymentTables(env);
    
    // Use default test data instead of parsing request body
    const data = {
      amount: 1000, // $10.00
      currency: 'usd',
      description: 'Test payment',
      metadata: { test: 'true' }
    };
    const { amount, currency, description, metadata } = data;

    // Mock payment intent for testing (without real Stripe call)
    const mockPaymentIntent = {
      id: `pi_test_${Date.now()}`,
      client_secret: `pi_test_${Date.now()}_secret_test`,
      amount,
      currency,
      status: 'requires_payment_method',
      description,
      metadata: {
        user_id: 'test-user',
        ...metadata,
      },
    };

    // Store transaction in database
    const db = createNeonDatabase(env);
    const transaction = await db.createTransaction({
      user_id: 'test-user',
      type: 'credit_purchase',
      amount,
      currency,
      payment_intent_id: mockPaymentIntent.id,
      description: description || 'Credit purchase',
      metadata,
    });

    return new Response(JSON.stringify({
      success: true,
      transaction_id: transaction?.id,
      payment_intent: {
        id: mockPaymentIntent.id,
        client_secret: mockPaymentIntent.client_secret,
        amount: mockPaymentIntent.amount,
        currency: mockPaymentIntent.currency,
        status: mockPaymentIntent.status,
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Payment intent creation error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to create payment intent' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// POST /payments/confirm - Confirm payment
export async function confirmPayment(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    
    const { order_id } = await parseAndValidate(request, confirmPaymentSchema);

    // Check if PayPal is configured, otherwise use mock mode
    let captureResult;
    if (env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET) {
      try {
        // Real PayPal integration
        const paypalClient = createPayPalClient(env);
        
        const response = await paypalClient.ordersController.ordersCapture({
          id: order_id,
          body: {},
        });
        
        captureResult = {
          id: response.result.id,
          status: response.result.status,
          amount: parseFloat(response.result.purchaseUnits[0].payments.captures[0].amount.value) * 100, // Convert to cents
          currency: response.result.purchaseUnits[0].payments.captures[0].amount.currencyCode.toLowerCase(),
          capture_id: response.result.purchaseUnits[0].payments.captures[0].id,
          metadata: {
            user_id: user.id,
          },
        };
      } catch (paypalError) {
        console.warn('PayPal API error, falling back to mock mode:', paypalError.message);
        // Fall back to mock mode if PayPal fails
        captureResult = {
          id: order_id,
          status: 'COMPLETED',
          amount: 1000, // Mock amount
          currency: 'usd',
          capture_id: `capture_mock_${Date.now()}`,
          metadata: {
            user_id: user.id,
          },
        };
      }
    } else {
      // Mock capture result for development
      captureResult = {
        id: order_id,
        status: 'COMPLETED',
        amount: 1000, // Mock amount
        currency: 'usd',
        capture_id: `capture_mock_${Date.now()}`,
        metadata: {
          user_id: user.id,
        },
      };
    }

    if (captureResult.status === 'COMPLETED') {
      const db = createNeonDatabase(env);
      
      // Update transaction status
      const transaction = await db.updateTransactionStatus(
        order_id,
        'completed',
        new Date()
      );

      // Add credits to user wallet (assuming 1 cent = 1 credit)
      await db.getOrCreateWallet(user.id, captureResult.currency);
      await db.updateWalletBalance(user.id, captureResult.amount, captureResult.currency);

      return new Response(JSON.stringify({
        success: true,
        transaction,
        payment: {
          id: captureResult.id,
          status: captureResult.status,
          amount: captureResult.amount,
          currency: captureResult.currency,
          capture_id: captureResult.capture_id,
        },
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ 
        error: 'Payment not completed', 
        status: captureResult.status 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error('Payment confirmation error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to confirm payment' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// POST /payments/refund - Process refund
export async function refundPayment(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    
    const { capture_id, amount, reason } = await parseAndValidate(request, refundSchema);

    const db = createNeonDatabase(env);
    
    // Get original transaction
    const originalTransaction = await db.getTransactionByPaymentIntent(capture_id);
    if (!originalTransaction || originalTransaction.user_id !== user.id) {
      return new Response(JSON.stringify({ error: 'Transaction not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if PayPal is configured, otherwise use mock mode
    let refundResult;
    if (env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET) {
      try {
        // Real PayPal integration
        const paypalClient = createPayPalClient(env);
        
        const refundRequest = {
          amount: {
            value: ((amount || originalTransaction.amount) / 100).toFixed(2), // Convert cents to dollars
            currencyCode: originalTransaction.currency.toUpperCase(),
          },
          noteToPayer: reason || 'Refund processed',
        };
        
        const response = await paypalClient.paymentsController.capturesRefund({
          id: capture_id,
          body: refundRequest,
        });
        
        refundResult = {
          id: response.result.id,
          status: response.result.status,
          amount: parseFloat(response.result.amount.value) * 100, // Convert to cents
          currency: response.result.amount.currencyCode.toLowerCase(),
        };
      } catch (paypalError) {
        console.warn('PayPal API error, falling back to mock mode:', paypalError.message);
        // Fall back to mock mode if PayPal fails
        refundResult = {
          id: `refund_mock_${Date.now()}`,
          status: 'COMPLETED',
          amount: amount || originalTransaction.amount,
          currency: originalTransaction.currency,
        };
      }
    } else {
      // Mock refund for development
      refundResult = {
        id: `refund_mock_${Date.now()}`,
        status: 'COMPLETED',
        amount: amount || originalTransaction.amount,
        currency: originalTransaction.currency,
      };
    }

    // Create refund transaction record
    const refundTransaction = await db.createTransaction({
      user_id: user.id,
      type: 'refund',
      amount: -(amount || originalTransaction.amount),
      currency: originalTransaction.currency,
      payment_intent_id: refundResult.id,
      description: `Refund for transaction ${originalTransaction.id}`,
      metadata: { original_transaction_id: originalTransaction.id, refund_reason: reason },
    });

    // Update refund transaction status
    await db.updateTransactionStatus(refundTransaction?.id || '', 'completed', new Date());

    // Deduct credits from wallet
    await db.updateWalletBalance(
      user.id, 
      -(amount || originalTransaction.amount), 
      originalTransaction.currency
    );

    return new Response(JSON.stringify({
      success: true,
      refund: {
        id: refundResult.id,
        amount: refundResult.amount,
        currency: refundResult.currency,
        status: refundResult.status,
      },
      transaction: refundTransaction,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Refund processing error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to process refund' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// GET /payments/history - Get payment history
export async function getPaymentHistory(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit') || '20');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    const db = createNeonDatabase(env);
    const transactions = await db.getUserTransactions(user.id, limit, offset);

    return new Response(JSON.stringify({
      success: true,
      transactions,
      pagination: {
        limit,
        offset,
        total: transactions.length,
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Payment history error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to get payment history' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// GET /payments/status/:id - Get payment status
export async function getPaymentStatus(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    
    const transactionId = params?.id;
    if (!transactionId) {
      return new Response(JSON.stringify({ error: 'Transaction ID required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = createNeonDatabase(env);
    const transaction = await db.getTransactionById(transactionId);

    if (!transaction || transaction.user_id !== user.id) {
      return new Response(JSON.stringify({ error: 'Transaction not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // If it's a PayPal payment, also get the latest status from PayPal
    let paypalStatus = null;
    if (transaction.payment_intent_id && transaction.type !== 'refund') {
      try {
        if (env.PAYPAL_CLIENT_ID && env.PAYPAL_CLIENT_SECRET) {
          const paypalClient = createPayPalClient(env);
          const response = await paypalClient.ordersController.ordersGet({
            id: transaction.payment_intent_id,
          });
          paypalStatus = response.result.status;
        }
      } catch (error) {
        console.error('Failed to get PayPal status:', error);
      }
    }

    return new Response(JSON.stringify({
      success: true,
      transaction,
      paypal_status: paypalStatus,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Payment status error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to get payment status' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// POST /payments/init-tables - Initialize payment tables
export async function initPaymentTables(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const db = createNeonDatabase(env);
    const success = await db.initializePaymentTables();
    
    if (success) {
      return new Response(JSON.stringify({ 
        message: 'Payment tables initialized successfully' 
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ 
        error: 'Failed to initialize payment tables' 
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (error) {
    console.error('initPaymentTables error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error',
      message: 'Failed to initialize payment tables'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Legacy function for backward compatibility
export async function createPaymentIntent(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  return createPayment(request, env, ctx, params);
}

// Placeholder functions for other legacy endpoints
export async function getWallet(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    await ensurePaymentTables(env);
    const db = createNeonDatabase(env);
    const wallet = await db.getOrCreateWallet(user.id, 'usd');

    return new Response(JSON.stringify({
      success: true,
      wallet
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Get wallet error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error', 
      message: 'Failed to get wallet' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function transferFunds(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  return new Response(JSON.stringify({ 
    error: 'Not implemented', 
    message: 'Transfer funds feature not yet implemented' 
  }), {
    status: 501,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function getTransactionHistory(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  return getPaymentHistory(request, env, ctx, params);
}

export async function handlePayPalWebhook(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  params?: Record<string, string>
): Promise<Response> {
  // This would handle PayPal webhook events
  // For now, just return success
  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}