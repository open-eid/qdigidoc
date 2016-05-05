/*
 * QDigiDocCrypto
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

#include "TreeWidget.h"

#include "CryptoDoc.h"

#include <client/FileDialog.h>
#include <common/Common.h>

#include <QtCore/QStandardPaths>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QHeaderView>
#include <QtGui/QMessageBox>
#endif
#include <QtGui/QKeyEvent>

using namespace Crypto;

TreeWidget::TreeWidget( QWidget *parent )
:	QTreeView( parent )
,	m(0)
{}

void TreeWidget::clicked( const QModelIndex &index )
{
	switch( index.column() )
	{
	case CDocumentModel::Save:
	{
		QString dest = FileDialog::getSaveFileName(qApp->activeWindow(),
			tr("Save file"), QString("%1/%2")
				.arg(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
				.arg(m->index(index.row(), CDocumentModel::Name).data().toString()));
		if( !dest.isEmpty() )
			m->copy( index, dest );
		break;
	}
	case CDocumentModel::Remove: model()->removeRow( index.row() ); break;
	default: break;
	}
}

void TreeWidget::keyPressEvent( QKeyEvent *e )
{
	QModelIndexList i = selectionModel()->selectedRows();
	if( !isColumnHidden( CDocumentModel::Remove ) && hasFocus() && !i.isEmpty() && i[0].isValid() )
	{
		switch( e->key() )
		{
		case Qt::Key_Delete:
			model()->removeRow( i[0].row() );
			e->accept();
			break;
		case Qt::Key_Return:
			m->open( i[0] );
			e->accept();
			break;
		default: break;
		}
	}
	QTreeView::keyPressEvent( e );
}

void TreeWidget::setDocumentModel( CDocumentModel *model )
{
	setModel( m = model );
	header()->setStretchLastSection( false );
	header()->setSectionResizeMode(QHeaderView::ResizeToContents);
	header()->setSectionResizeMode(CDocumentModel::Name, QHeaderView::Stretch);
	setColumnHidden( CDocumentModel::Mime, true );
	connect( this, SIGNAL(clicked(QModelIndex)), SLOT(clicked(QModelIndex)) );
	connect( this, SIGNAL(doubleClicked(QModelIndex)), m, SLOT(open(QModelIndex)) );
}
