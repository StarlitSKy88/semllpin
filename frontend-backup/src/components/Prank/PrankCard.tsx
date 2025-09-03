import { Avatar, Button, Card, Space, Typography } from 'antd';;

import React from 'react';

import { Heart, Share, Eye } from 'lucide-react';

const { Text } = Typography;

interface Prank {
  id: string;
  funny_title: string;
  description: string;
  prank_type: string;
  emoji_reaction: string;
  laugh_count: number;
  share_count: number;
  paid_amount: number;
  user?: {
    id: string;
    username: string;
    avatar_url?: string;
  };
}

interface PrankCardProps {
  prank: Prank;
  compact?: boolean;
  showActions?: boolean;
}

const PrankCard: React.FC<PrankCardProps> = ({ prank, compact = false, showActions = true }) => {
  return (
    <Card 
      className={`${compact ? 'p-3' : 'p-4'} hover:shadow-lg transition-shadow`}
      size={compact ? 'small' : 'default'}
    >
      <Space direction="vertical" className="w-full">
        <div className="flex items-center justify-between">
          <Space>
            <Avatar size="small">{prank.user?.username?.[0]}</Avatar>
            <div>
              <Text strong>{prank.funny_title}</Text>
              <br />
              <Text type="secondary" className="text-xs">
                {prank.user?.username} • {prank.prank_type}
              </Text>
            </div>
          </Space>
          <Text className="text-lg">{prank.emoji_reaction}</Text>
        </div>
        
        <Text className="text-gray-600">{prank.description}</Text>
        
        {showActions && (
          <div className="flex items-center justify-between pt-2">
            <Space>
              <Button type="text" icon={<Heart size={16} />} size="small">
                {prank.laugh_count}
              </Button>
              <Button type="text" icon={<Share size={16} />} size="small">
                {prank.share_count}
              </Button>
              <Button type="text" icon={<Eye size={16} />} size="small">
                查看
              </Button>
            </Space>
            <Text type="secondary" className="text-xs">
              ¥{prank.paid_amount}
            </Text>
          </div>
        )}
      </Space>
    </Card>
  );
};

export default PrankCard;