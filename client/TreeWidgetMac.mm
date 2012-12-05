/*
 * QDigiDocClient
 *
 * Copyright (C) 2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2012 Raul Metsma <raul@innovaatik.ee>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#import "TreeWidget.h"
#import "DigiDoc.h"

#import <QtGui/QAbstractItemView>

#import <objc/runtime.h>

#import <Quartz/Quartz.h>

@interface NSView ( NSViewQuickPreview ) <QLPreviewPanelDataSource, QLPreviewPanelDelegate>

- (QAbstractItemView *)view;
- (void)setView:(QAbstractItemView *)view;
- (BOOL)acceptsPreviewPanelControl:(QLPreviewPanel *)panel;
- (void)beginPreviewPanelControl:(QLPreviewPanel *)panel;
- (void)endPreviewPanelControl:(QLPreviewPanel *)panel;
- (BOOL)previewPanel:(QLPreviewPanel *)panel handleEvent:(NSEvent *)event;

@property QAbstractItemView *view;

@end

@implementation NSView ( NSViewQuickPreview )

@dynamic view;

- (QAbstractItemView *)view
{
	return (__bridge QAbstractItemView*)objc_getAssociatedObject( self, "QAbstractItemView" );
}

- (void)setView:(QAbstractItemView *)view
{
	objc_setAssociatedObject( self, "QAbstractItemView", (__bridge id)view, OBJC_ASSOCIATION_ASSIGN );
}

- (BOOL)acceptsPreviewPanelControl:(QLPreviewPanel *)panel
{
	Q_UNUSED(panel)
	return self.view ? YES : NO;
}

- (void)beginPreviewPanelControl:(QLPreviewPanel *)panel
{
	panel.dataSource = self;
	panel.delegate = self;
	panel.currentPreviewItemIndex = self.view->currentIndex().row();
}

- (void)endPreviewPanelControl:(QLPreviewPanel *)panel
{
    Q_UNUSED(panel)
	self.view->setCurrentIndex( self.view->model()->index( panel.currentPreviewItemIndex, 0 ) );
	self.view = nil;
}

- (NSInteger)numberOfPreviewItemsInPreviewPanel:(QLPreviewPanel *)panel
{
	Q_UNUSED(panel)
	return self.view->model()->rowCount();
}

- (id <QLPreviewItem>)previewPanel:(QLPreviewPanel *)panel previewItemAtIndex:(NSInteger)index
{
	Q_UNUSED(panel)
	DocumentModel *model = qobject_cast<DocumentModel*>(self.view->model());
	QByteArray path = model->index( index, 0 ).data( Qt::UserRole ).toString().toUtf8();
	return [NSURL fileURLWithPath:[NSString stringWithUTF8String: path.constData()]];
}

- (BOOL)previewPanel:(QLPreviewPanel *)panel handleEvent:(NSEvent *)event
{
	switch ([event type]) {
		case NSKeyUp:
		case NSKeyDown:
			self.view->setCurrentIndex(
				self.view->model()->index([panel currentPreviewItemIndex], 0));
			return YES;
		default:
			return NO;
	}

}

@end

void TreeWidget::setPreviewIndex( const QModelIndex &index )
{
	if ([[QLPreviewPanel sharedPreviewPanel] isVisible])
		[QLPreviewPanel sharedPreviewPanel].currentPreviewItemIndex = index.row();
}

void TreeWidget::showPreview()
{
	NSView *view = (__bridge NSView*)(void*)winId();
	view.view = this;
	[[QLPreviewPanel sharedPreviewPanel] makeKeyAndOrderFront:view];
}

void TreeWidget::hidePreview()
{
	if ([[QLPreviewPanel sharedPreviewPanel] isVisible])
		[[QLPreviewPanel sharedPreviewPanel] orderOut:nil];
}
