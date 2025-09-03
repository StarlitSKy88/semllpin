-- Create payments table
CREATE TABLE payments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  annotation_id UUID REFERENCES annotations(id) ON DELETE SET NULL,
  amount DECIMAL(10, 2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  payment_method VARCHAR(50) NOT NULL, -- stripe, paypal, alipay, wechat, etc.
  payment_intent_id VARCHAR(255), -- External payment provider ID
  transaction_id VARCHAR(255), -- External transaction ID
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded')),
  description TEXT,
  metadata JSONB DEFAULT '{}'::jsonb, -- Additional payment data
  fee_amount DECIMAL(10, 2) DEFAULT 0, -- Platform fee
  net_amount DECIMAL(10, 2), -- Amount after fees
  refund_amount DECIMAL(10, 2) DEFAULT 0,
  refund_reason TEXT,
  processed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_payments_user_id ON payments(user_id);
CREATE INDEX idx_payments_annotation_id ON payments(annotation_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_payment_method ON payments(payment_method);
CREATE INDEX idx_payments_payment_intent_id ON payments(payment_intent_id);
CREATE INDEX idx_payments_transaction_id ON payments(transaction_id);
CREATE INDEX idx_payments_created_at ON payments(created_at);
CREATE INDEX idx_payments_processed_at ON payments(processed_at);

-- Create composite indexes
CREATE INDEX idx_payments_user_status ON payments(user_id, status);
CREATE INDEX idx_payments_status_created_at ON payments(status, created_at DESC);

-- Create trigger to update updated_at
CREATE TRIGGER update_payments_updated_at
  BEFORE UPDATE ON payments
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create trigger to calculate net amount
CREATE OR REPLACE FUNCTION calculate_net_amount()
RETURNS TRIGGER AS $$
BEGIN
  NEW.net_amount = NEW.amount - COALESCE(NEW.fee_amount, 0);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER calculate_payments_net_amount
  BEFORE INSERT OR UPDATE ON payments
  FOR EACH ROW
  EXECUTE FUNCTION calculate_net_amount();

-- Create trigger to set processed_at when status changes to completed
CREATE OR REPLACE FUNCTION set_processed_at()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
    NEW.processed_at = CURRENT_TIMESTAMP;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_payments_processed_at
  BEFORE UPDATE ON payments
  FOR EACH ROW
  EXECUTE FUNCTION set_processed_at();

-- Create payment statistics view
CREATE VIEW payment_stats AS
SELECT 
  DATE_TRUNC('day', created_at) as date,
  payment_method,
  currency,
  COUNT(*) as transaction_count,
  SUM(amount) as total_amount,
  SUM(fee_amount) as total_fees,
  SUM(net_amount) as total_net,
  AVG(amount) as avg_amount,
  COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_count,
  COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count,
  COUNT(CASE WHEN status = 'refunded' THEN 1 END) as refunded_count
FROM payments
GROUP BY DATE_TRUNC('day', created_at), payment_method, currency
ORDER BY date DESC;

-- Create user payment summary view
CREATE VIEW user_payment_summary AS
SELECT 
  u.id as user_id,
  u.username,
  u.email,
  COUNT(p.id) as total_payments,
  SUM(CASE WHEN p.status = 'completed' THEN p.amount ELSE 0 END) as total_spent,
  SUM(CASE WHEN p.status = 'completed' THEN 1 ELSE 0 END) as successful_payments,
  SUM(CASE WHEN p.status = 'failed' THEN 1 ELSE 0 END) as failed_payments,
  MAX(p.created_at) as last_payment_at,
  AVG(CASE WHEN p.status = 'completed' THEN p.amount END) as avg_payment_amount
FROM users u
LEFT JOIN payments p ON u.id = p.user_id
GROUP BY u.id, u.username, u.email;

-- Create function to get payment history
CREATE OR REPLACE FUNCTION get_user_payment_history(
  p_user_id UUID,
  p_limit INTEGER DEFAULT 20,
  p_offset INTEGER DEFAULT 0
)
RETURNS TABLE (
  id UUID,
  annotation_id UUID,
  amount DECIMAL,
  currency VARCHAR,
  payment_method VARCHAR,
  status VARCHAR,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE,
  processed_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    p.id,
    p.annotation_id,
    p.amount,
    p.currency,
    p.payment_method,
    p.status,
    p.description,
    p.created_at,
    p.processed_at
  FROM payments p
  WHERE p.user_id = p_user_id
  ORDER BY p.created_at DESC
  LIMIT p_limit
  OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;