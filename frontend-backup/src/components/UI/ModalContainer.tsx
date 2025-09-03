import React from 'react';
import { useUIStore } from '../../stores/uiStore';
import PrankCreateModal from '../Prank/PrankCreateModal';

import ProfileModal from '../Profile/ProfileModal';
import SettingsModal from '../Settings/SettingsModal';
import TopUpModal from '../Wallet/TopUpModal';
import ShareModal from '../Social/ShareModal';

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
interface ModalContainerProps {
  // 可以添加额外的props
}

const ModalContainer: React.FC<ModalContainerProps> = () => {
  const { modals } = useUIStore();

  const renderModal = (modal: { type: string; id: string; props?: Record<string, unknown> }) => {
    switch (modal.type) {
      case 'prank-create':
        return <PrankCreateModal key={modal.id} modalId={modal.id} {...modal.props} />;
      case 'prank-detail':
        // PrankDetailModal 暂时禁用，等待模块解析问题修复
        return null;
      case 'payment':
        // PaymentModal 暂时禁用，等待模块创建
        return null;
      case 'share':
        return <ShareModal key={modal.id} modalId={modal.id} {...modal.props} />;
      case 'profile':
        return <ProfileModal key={modal.id} modalId={modal.id} {...modal.props} />;
      case 'settings':
        return <SettingsModal key={modal.id} modalId={modal.id} {...modal.props} />;
      case 'topup':
        return <TopUpModal key={modal.id} {...modal.props} />;
      default:
        return null;
    }
  };

  return (
    <>
      {modals.map((modal) => (
        <div key={modal.id}>
          {renderModal(modal)}
        </div>
      ))}
    </>
  );
};

export default ModalContainer;