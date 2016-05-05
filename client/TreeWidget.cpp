/*
 * QDigiDocClient
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

#include "Application.h"
#include "DigiDoc.h"
#include "FileDialog.h"

#include <QtCore/QStandardPaths>
#include <QtCore/QUrl>
#include <QtGui/QKeyEvent>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>

TreeWidget::TreeWidget( QWidget *parent )
:	QTreeView( parent )
,	m(0)
{}

TreeWidget::~TreeWidget()
{
	hidePreview();
}

void TreeWidget::clicked( const QModelIndex &index )
{
	setPreviewIndex( index );
	switch( index.column() )
	{
	case DocumentModel::Save:
	{
		QString dest = FileDialog::getSaveFileName(qApp->activeWindow(),
			tr("Save file"), QString("%1/%2")
				.arg(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
				.arg(m->index(index.row(), DocumentModel::Name).data(Qt::UserRole).toString()));
		if( !dest.isEmpty() )
			m->save( index, dest );
		break;
	}
	case DocumentModel::Remove: model()->removeRow( index.row() ); break;
	default: break;
	}
}

void TreeWidget::keyPressEvent( QKeyEvent *e )
{
	QModelIndexList i = selectionModel()->selectedRows();
	if( hasFocus() && !i.isEmpty() && i[0].isValid() )
	{
		switch( e->key() )
		{
		case Qt::Key_Space:
			showPreview();
			break;
		case Qt::Key_Up:
		case Qt::Key_Down:
		{
			QTreeView::keyPressEvent( e );
			QModelIndexList i = selectionModel()->selectedRows();
			if( !i.isEmpty() )
				setPreviewIndex( i[0] );
			return;
		}
		case Qt::Key_Escape:
			hidePreview();
			break;
		case Qt::Key_Delete:
			if( isColumnHidden( DocumentModel::Remove ) )
				break;
			model()->removeRow( i[0].row() );
			e->accept();
			break;
		case Qt::Key_Return:
			qobject_cast<DocumentModel*>(model())->open( i[0] );
			e->accept();
			break;
		default: break;
		}
	}
	QTreeView::keyPressEvent( e );
}

void TreeWidget::setDocumentModel( DocumentModel *model )
{
	setModel( m = model );
	header()->setStretchLastSection( false );
	header()->setSectionResizeMode(QHeaderView::ResizeToContents);
	header()->setSectionResizeMode(DocumentModel::Name, QHeaderView::Stretch);
	setColumnHidden( DocumentModel::Mime, true );
	connect( this, SIGNAL(clicked(QModelIndex)), SLOT(clicked(QModelIndex)) );
	connect( this, SIGNAL(doubleClicked(QModelIndex)), model, SLOT(open(QModelIndex)) );
}

#ifndef Q_OS_MAC
void TreeWidget::setPreviewIndex( const QModelIndex & ) {}
void TreeWidget::showPreview() {}
void TreeWidget::hidePreview() {}
#endif
