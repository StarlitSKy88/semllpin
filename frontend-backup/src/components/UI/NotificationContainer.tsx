import React, { useEffect } from 'react';
import { useUIStore } from '../../stores/uiStore';
import { notification } from 'antd';

const NotificationContainer: React.FC = () => {
  const { notifications, removeNotification } = useUIStore();
  const [api, contextHolder] = notification.useNotification();

  useEffect(() => {
    notifications.forEach((notif) => {
      api[notif.type]({
        message: notif.title,
        description: notif.message,
        duration: notif.duration ? notif.duration / 1000 : 5,
        onClose: () => removeNotification(notif.id),
        btn: notif.action ? (
          <button
            onClick={() => {
              notif.action?.onClick();
              removeNotification(notif.id);
            }}
            className="text-primary-600 hover:text-primary-700 font-medium"
          >
            {notif.action.label}
          </button>
        ) : undefined,
      });
      
      // 自动移除通知
      if (notif.duration) {
        setTimeout(() => {
          removeNotification(notif.id);
        }, notif.duration);
      }
    });
  }, [notifications, api, removeNotification]);

  return contextHolder;
};

export default NotificationContainer;